# Civic affairs

The Civic Defence Establishment is a small government department that worries about things for a
living. It is a parody of a Ministry of Defence with a little cyber capability bolted on the side,
and under the costume it is a working toolchain: real sensors, real intelligence platforms, real
intake channels, wired together to behave like a department of state.

Like any ministry, it runs on worry. Someone at the top, the Patrician, decides what the
Establishment will (have to) be afraid of this year. That fear travels downhill and turns into work. The work
travels back up as assessments. The Patrician reads them, decides what to do or not do, and decides
what to interfere with next. Round it goes.

That loop is the whole design. The question a ministry actually answers is rarely "what happened".
It is "what are we going to pay attention to". And the joke, as with most ministries, is less about
what they know than about what they bother to look at.

## The divisions

The Receiving Desk leaves the light on. It is the open door, the channel for the things nobody asked
for: a tip, a researcher's disclosure, the occasional crank with a PGP key. It is the Ministry's own
ear to the ground, as distinct from the directed collection that comes in from Surveys, the secret
service, which finds only what it is sent to find. A department needs both, because the directed eye
goes blind in exactly the shape of its instructions, and the unbidden report is how it notices the
fire it was not watching for.

The Quiet Room is where fragments become something. Network sensors, host logs, the patient and
slightly thankless business of turning noise into a thing you can put a number against. It does not
decide what anything means. It characterises: this came from there, it looks like that, here is how
much we trust it.

The Long Table is where the fragments are argued into an assessment. It corroborates, weighs, and
writes the thing down. It does not, deliberately, decide what to do about any of it. It establishes
what is happening and how sure anyone is, and then it stops. That line between knowing and deciding
is old and on purpose: analysts assess, the principal decides.

The Patrician reads the brief and decides. Warn the operator, lean on the vendor, let the disclosure
clock run, or do nothing and keep watching. None of these are technical choices. They are political
ones, with a cost on every side, and they live here. That is not a flaw in the machine. It is the
point of it.

## Two ministerial habits

Reliability scoring is armour as much as arithmetic. "Source reliability: 2. Credibility: unknown."
is not really a claim about the world. It is a way to move a rumour upstairs while nobody has sworn
it is true. Useful, and very ministerial.

The department runs on rhythm, not on alarms. There is a brief every morning whether anything
happened, because "nothing new on the water this week" is itself a report. A department that only
spoke when startled would not be doing its job. The job is sustained attention.

## Under the costume

Stripped of the parody it is a real, dockerised stack: Suricata and Zeek for network sensing, Wazuh
for host telemetry, MISP for indicator handling, OpenCTI as the Long Table, Shuffle for automation,
and GlobaLeaks for anonymous intake. Each maps onto a division, and the whole thing runs from one
control script.

If you want to stand it up, read the parts, or follow a signal from a sensor through to an
assessment, that can be found in [README-technical.md](README-technical.md). There is also a small
end-to-end simulation that walks one case (a targeted water-treatment vulnerability) from the
sensors to a consolidated assessment, so the story can be watched happening rather than taken on
trust.

## Licence

[Unlicence](LICENCE)
