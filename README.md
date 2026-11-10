<p align="center">
  <img src="assets/logo.png" alt="HondaLink Home Assistant integration logo" width="180">
</p>

# HondaLink (read-only) for Home Assistant

An unofficial, **read-only** Home Assistant custom integration for HondaLink connected vehicles.
It shows the status your car reports to Honda's cloud. It cannot control the car.

> This project is not affiliated with, endorsed by, or supported by Honda. HondaLink is a
> trademark of its respective owner.

This is a fork of [Space-C0wboy/ha-hondalink](https://github.com/Space-C0wboy/ha-hondalink), which
is itself a fork of [daviddelahoz/ha-hondalink](https://github.com/daviddelahoz/ha-hondalink). The
remote-control features of those projects have been removed.

## What "read-only" means

- There is no lock entity and there are no engine start/stop, horn or lights buttons.
- The HondaLink remote PIN is never asked for, stored or sent.
- Sign-in requests go to Honda's identity server (`identity.services.honda.com`): client
  registration and token generation. They send your email and password and nothing else.
- Every request to the vehicle API (`wsc.hondaweb.com`) goes through an allowlist in `api.py`.
  Only these are permitted: vehicle lookup, reading the stored dashboard status, and the PIN-free
  "Refresh" request (and its result) that asks the car to report fresh status. Anything else is
  refused before it is sent, and so is any request body containing a PIN.
- If you previously used another fork that stored a remote PIN or lock/unlock command codes in
  the config entry, they are deleted the first time this integration starts.

## What it shows

Sensors:

- Fuel level, range, odometer, oil life
- 12 V battery status
- Tyre pressures (each tyre)
- Vehicle speed, cabin temperature
- Maintenance items (Maintenance Minder)
- Last update time
- Diagnostic: sign-ins in the last 24 hours

Binary sensors:

- Doors (each door and any-open), windows (each window and any-open), hood, trunk
- Door locks (status only; you cannot lock or unlock from Home Assistant)
- Lights, warning lamp, engine running

Other:

- Device tracker from the vehicle's GPS location, when Honda returns it
- A "Refresh" button that asks the car for fresh status

Fields are only populated when Honda's dashboard data contains them, so some entities may be
unavailable on some vehicles.

## Account safety

Using an unofficial API on a real account carries some risk. This integration tries to keep its
traffic low and predictable:

- Polls the stored status every 15 minutes by default. The minimum is 5 minutes.
- Limits failed password sign-ins, which are what can lock an account, to 3 per hour and 8 per
  24 hours. A sign-in whose outcome is unknown (for example a timeout) counts as failed.
- Also limits all password sign-ins, successful or not, to 6 per hour and 100 per 24 hours, as a
  guard against a sign-in loop.
- Once any limit is reached it does not try to sign in again until the rolling window has passed.
  The attempt history is saved, so restarting Home Assistant or re-entering the password does not
  reset it.
- On repeated failures it backs off: 15, then 30, then 60 minutes between attempts.
- An authentication failure stops polling and asks you to sign in again (re-authentication)
  instead of retrying with the same credentials.
- "Refresh" can be used at most once every 15 minutes. Each press asks the car's telematics unit
  to wake up and report, so use it sparingly.

These limits reduce the risk but cannot remove it. Honda can change or block this private API at
any time, and this fork has not yet been verified on every model year. Its checks are covered by
offline unit tests only.

## Installation

### Manual

Copy the contents of this repository into:

```text
/config/custom_components/hondalink/
```

Then restart Home Assistant.

### HACS (custom repository)

1. In Home Assistant, open HACS.
2. Open the menu and choose Custom repositories.
3. Add `https://github.com/ddk220-light/ha-hondalink-readonly` with category `Integration`.
4. Install `HondaLink (read-only)`.
5. Restart Home Assistant.

This integration uses the domain `hondalink`, so it replaces (and cannot run alongside) the
upstream HondaLink integrations. Remove those first.

## Setup

Go to:

```text
Settings > Devices & services > Add integration > HondaLink (read-only)
```

The setup form asks for:

- HondaLink email
- HondaLink password
- VIN (optional, if the vehicle can be found automatically)
- Name (optional display name)

If no vehicle is found automatically, enter the VIN manually.

After setup, the integration options let you change the polling interval.

## If you want remote lock or remote start

This fork deliberately does not support them. Use one of the upstream projects instead:

- [daviddelahoz/ha-hondalink](https://github.com/daviddelahoz/ha-hondalink)
- [Space-C0wboy/ha-hondalink](https://github.com/Space-C0wboy/ha-hondalink)

## Troubleshooting

### Could not connect to HondaLink

Restart Home Assistant after updating the custom component, then try setup again. The config flow
logs a generic error and, where relevant, an allowlisted error code, so check the Home Assistant
logs for:

```text
HondaLink connection failed during config flow
```

### Invalid credentials

Confirm that the same email and password work in the HondaLink mobile app. Some HondaLink accounts
need you to accept updated terms or complete account verification in the app before sign-in
succeeds.

### No vehicle discovered

Enter the VIN manually in the setup form. The integration will still try to fetch the vehicle
details by VIN after sign-in.

### Data stopped updating

Check the "Sign-ins in the last 24 hours" sensor (its `failed` attribute counts failed sign-ins)
and the Home Assistant logs. If a sign-in limit was reached, or the integration is backing off after failures, it resumes on its own once the
window passes. If Home Assistant shows a re-authentication prompt, sign in again there.

## Security and privacy

- Your HondaLink email and password are stored in the Home Assistant config entry so the
  integration can sign in again when its token expires. No PIN is stored.
- The Honda app `CLIENT_ID` and `CLIENT_SECRET` values are app-level credentials observed from the
  HondaLink mobile app, not user-specific credentials. Honda may rotate or revoke them at any time,
  which would stop sign-in from working until the integration is updated.
- The diagnostics download redacts credentials, tokens, VIN, email and GPS coordinates. Still,
  do not share logs or diagnostics that might contain them.

## Known limitations

- HondaLink is a private cloud API; reliability depends on Honda's service and endpoint
  compatibility.
- EV fields are shown only when Honda's dashboard data returns actual values.
- Not verified on every model year, market or subscription.

## Credits and licence

MIT licence; see [LICENSE](LICENSE).

- [David De La Hoz](https://github.com/daviddelahoz): original integration
  ([daviddelahoz/ha-hondalink](https://github.com/daviddelahoz/ha-hondalink)).
- [Space-C0wboy](https://github.com/Space-C0wboy): the fork this one is based on
  ([Space-C0wboy/ha-hondalink](https://github.com/Space-C0wboy/ha-hondalink)).
- Contributors to the upstream projects, including
  [Brian Crook (@bcrook)](https://github.com/bcrook) (fix for 401 errors after the HondaLink 5.5.0
  gateway update), [@berkman](https://github.com/berkman) (options-flow fixes) and
  [Constantine Yevdiukhin (@Costya-Y)](https://github.com/Costya-Y) (security and reliability
  hardening, re-authentication flow, door lock-state logic, offline tests).
