"""CLI entry point: ``python -m yantrasim [--supabase|--mqtt] --interval 2``."""
from __future__ import annotations

import argparse
import logging
import sys
import time

from yantracore import start_site_sync, stop_site_sync
from yantracore.runtime_config import TablePoller, coerce_float, resolve_value

from .commands import apply_command
from .sim import FleetSim
from .transports.base import StdoutTransport, Transport
from .transports.supabase import SupabaseTransport
from .transports.supabase import resolve_config as resolve_supabase_config

#: v0.18: non-secret runtime tunable this service reads live from
#: public.app_config (see supabase/0018_app_config.sql) — Supabase mode
#: only (mqtt/stdout modes have no Supabase project to poll for it).
CONFIG_KEYS = ("SIM_INTERVAL",)
DEFAULT_INTERVAL_S = 2.0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="yantrasim",
        description="Simulate a 10-AMR warehouse fleet emitting VDA 5050 v2.1 state.",
    )
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--supabase", action="store_true",
                      help="publish to Supabase via PostgREST bulk upsert (default)")
    mode.add_argument("--mqtt", action="store_true",
                      help="publish VDA 5050 topics to an MQTT broker (needs paho-mqtt)")
    mode.add_argument("--stdout", action="store_true",
                      help="print tick summaries instead of publishing")
    p.add_argument("--interval", type=float, default=None,
                   help="wall-clock seconds between ticks (default: live "
                        "from public.app_config's SIM_INTERVAL in "
                        "--supabase mode, else 2)")
    p.add_argument("--time-scale", type=float, default=5.0,
                   help="simulated seconds per wall second (default: 5)")
    p.add_argument("--ticks", type=int, default=0,
                   help="stop after N ticks (0 = run until Ctrl-C)")
    p.add_argument("--seed", type=int, default=42, help="RNG seed (default: 42)")
    p.add_argument("--url", default=None, help="Supabase URL (or env SUPABASE_URL)")
    p.add_argument("--key", default=None, help="Supabase anon key (or env SUPABASE_KEY)")
    p.add_argument("--site", default=None, metavar="SITE_ID",
                   help="site_id to stamp on every row and to poll commands "
                        "for (or env YANTRA_SITE_ID; default BLR-DC1). With "
                        "--ingest-key this must be the workspace's WS-<hex> id")
    p.add_argument("--ingest-key", default=None, metavar="yk_...",
                   help="write as a self-serve workspace's robot connector "
                        "(supabase/0019): sends x-yf-ingest-key on every "
                        "request, namespaces ids with '<site>-', skips "
                        "fleet_meta (or env YANTRA_INGEST_KEY). Prefer the env "
                        "var — argv is visible in `ps`")
    p.add_argument("--broker", default="localhost", help="MQTT broker host")
    p.add_argument("--port", type=int, default=1883, help="MQTT broker port")
    p.add_argument("--verbose", action="store_true", help="debug logging / full JSON")
    return p


def make_transport(args: argparse.Namespace, sim: FleetSim,
                   client=None) -> Transport:
    if args.mqtt:
        from .transports.mqtt import MqttTransport  # optional paho import lives here
        return MqttTransport(sim.robots, broker=args.broker, port=args.port)
    if args.stdout:
        return StdoutTransport(verbose=args.verbose)
    return SupabaseTransport(url=args.url, key=args.key, writer_id=sim.writer_id,
                             client=client, site=args.site,
                             ingest_key=args.ingest_key)


def main(argv: list[str] | None = None, client=None) -> int:
    """``client`` is an injectable httpx.Client (tests only) used for both
    the Supabase transport and the live app_config poll below."""
    args = build_parser().parse_args(argv)
    import os as _os
    _lvl = (logging.DEBUG if args.verbose else
            getattr(logging, _os.environ.get("YANTRA_LOG_LEVEL", "INFO").upper(),
                    logging.INFO))
    logging.basicConfig(
        level=_lvl,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    if not args.verbose:  # httpx request spam is DEBUG-grade for a demo
        logging.getLogger("httpx").setLevel(logging.WARNING)
    sim = FleetSim(seed=args.seed)
    try:
        transport = make_transport(args, sim, client=client)
    except ValueError as exc:
        # An ingest key that cannot work (malformed, or paired with a
        # non-workspace site) is refused at startup, not per tick.
        print(f"yantrasim: {exc}", file=sys.stderr)
        return 2

    # v0.18: SIM_INTERVAL from public.app_config when --interval wasn't
    # explicitly passed — Supabase mode only (mqtt/stdout have no
    # Supabase project to poll). Degrades quietly (see TablePoller) when
    # the migration isn't applied or there's no real backend at all.
    # v0.18.1: YANTRA_SITE_ID gets the same live wiring — same gate,
    # same degrade-quietly behavior — so an admin-console site change
    # reaches yantracore.site_id() (used when stamping rows) without a
    # restart.
    # Workspace mode (an ingest key) polls neither: app_config is not
    # readable with a key (0019 grants anon nothing outside the seven
    # fleet tables), and the site is pinned to the key's workspace anyway.
    config: TablePoller | None = None
    site_sync_started = False
    workspace_mode = getattr(transport, "ingest_key", None) is not None
    if not args.mqtt and not args.stdout and not workspace_mode:
        url, key = resolve_supabase_config(args.url, args.key)
        config = TablePoller(url, key, table="app_config", keys=CONFIG_KEYS,
                             client=client)
        config.poll_once()
        start_site_sync(url, key, client=client)
        site_sync_started = True

    def _interval() -> float:
        return resolve_value(args.interval, config, "SIM_INTERVAL",
                             DEFAULT_INTERVAL_S, coerce_float)

    interval = _interval()
    # Simulated seconds per tick; a zero --interval (fast-forward runs)
    # still advances sim time by one time-scale unit per tick.
    dt = interval * args.time_scale if interval > 0 else args.time_scale
    mode = "mqtt" if args.mqtt else ("stdout" if args.stdout else "supabase")
    print(f"yantrasim: {len(sim.robots)} AMRs, mode={mode}, "
          f"interval={interval}s, dt={dt}s/tick (Ctrl-C to stop)")
    try:
        while args.ticks <= 0 or sim.tick_count < args.ticks:
            out = sim.tick(dt_s=dt)
            transport.publish(out)
            # v0.2: execute human-approved operator commands (Supabase only).
            if hasattr(transport, "poll_commands"):
                transport.poll_commands(
                    lambda rid, cmd: apply_command(sim, rid, cmd))
            # v0.10: adopt inbound VDA 5050 orders (MQTT master control).
            if hasattr(transport, "poll_orders"):
                transport.poll_orders(
                    lambda rid, oid, ouid, nodes, actions:
                        sim.apply_order(rid, oid, ouid, nodes, actions))
            for e in out.events:
                logging.getLogger("yantrasim").info(
                    "event %s (%s): %s", e.kind, e.sev, e.msg)
            if args.ticks <= 0 or sim.tick_count < args.ticks:
                if config is not None:
                    config.maybe_poll()
                interval = _interval()
                dt = interval * args.time_scale if interval > 0 else args.time_scale
                time.sleep(interval)
    except KeyboardInterrupt:
        print("\nstopping...")
    finally:
        transport.close()
        if config is not None:
            config.close()
        if site_sync_started:
            stop_site_sync()
    return 0


if __name__ == "__main__":
    sys.exit(main())
