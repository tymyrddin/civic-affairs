# GlobaLeaks node setup

A fresh clone brings up a blank GlobaLeaks: the look and feel arrive from the repo,
but the node identity, the front-page texts, and the recipient account live in the
encrypted `globaleaks_globaleaks-data` volume, which is not in git. This guide records
the configuration of the running "Civic Defence Establishment" desk so it can be redone
by hand on a new instance. The values below are the live ones, copy them verbatim to
reproduce the desk exactly.

## Already in the repo

These come from the mounted files in `receiving-desk/globaleaks/` and need no action in
the admin interface:

- the logo (`logo.png`, painted on `#LogoBox` by `custom.css`)
- the page styling (`custom.css`)
- the page shell (`index.html`)

Leaving the admin-panel logo upload and Custom CSS box empty keeps the repo as the single
source. Anything entered there lives only in the volume and is lost on a clone.

## First access

The admin interface is HTTPS only. Host port 8082 maps to the container's 8443, so
`http://127.0.0.1:8082` returns an empty response; use `https://127.0.0.1:8082`. The
certificate is self-signed for localhost, so the browser warning is expected and can be
accepted.

The first visit runs the setup wizard. It creates the admin account and the platform
encryption keys. The admin password chosen here is the root of the instance: GlobaLeaks
encrypts the database against it, and there is no recovery path beyond the account
recovery key the wizard prints. Keeping that recovery key somewhere safe is worthwhile.

## Node identity

Under Settings, the recorded values are:

- Name: `Civil Reporting Office`
- Description: `Anonymous submission of civil infrastructure observations and notifications to the Civic Defence Establishment Receiving Desk.`
- Default language: English
- Maximum upload size: 30 MB
- Encryption: on

## Front-page texts

These are the customised strings that give the desk its voice. Each maps to a field in
the admin interface under Settings and the text customisation section.

Home page title:

```
Receiving Desk
```

Presentation:

```
The Civic Defence Establishment operates this portal for anonymous submissions concerning civil infrastructure security.

Reports may concern known or suspected vulnerabilities in systems of civic relevance, unusual activity near infrastructure sites, or material a person believes the Establishment ought to consider. The Receiving Desk assesses each submission for routing. Not all submissions result in further action.

The Establishment does not communicate with anonymous submitters after receipt. It does not confirm receipt. A case reference number, retrievable through this portal, is the only record of the transaction.

Persons wishing to submit through an identified channel may find contact details through the Establishment's main presence.
```

Question (the prompt above the submit button):

```
Do you have information about threats to civil infrastructure, vulnerabilities in systems of civic relevance, or other material you believe the Establishment ought to consider?
```

Submit button:

```
Submit a report
```

Channel selection prompt:

```
Select a reporting channel:
```

Disclaimer:

```
Submissions are received by the Civic Defence Establishment Receiving Desk. They are not forwarded to the City Watch as a matter of course, though material relevant to an active investigation may be shared under applicable legal instruments.

Anonymity depends on the conditions under which this portal is accessed. Using it over Tor, on a device not otherwise associated with the submitter's identity, offers reasonable protection. The Establishment cannot extend that protection to conditions of access it has no visibility into.

This portal is not for emergencies. If civil infrastructure is under active threat, contact the City Watch directly.
```

Footer:

```
Receiving Desk, Civic Defence Establishment. Not monitored continuously. For emergencies, contact the City Watch.
```

## Submission channel

A single context named `Default` carries a report retention of 90 days. It does not use
the stock questionnaire: a custom one named `Incident Report` replaces it, built under
Questionnaires in the admin interface and then selected on the context. Its structure is
two steps, both optional:

- Step `Description`: one free-text field (textarea) labelled `Description`, maximum length
  2000 characters.
- Step `Attachment`: one file-upload field labelled `Attach any supporting files (pcap,
  logs, screenshots)`, with multiple files allowed (multi-entry).

Recreating it: add the `Incident Report` questionnaire, add the two steps in that order,
place the one field in each, then set the `Default` context to use it.

## Recipients

Two accounts exist. The wizard creates the admin; the recipient is added afterwards under
Users:

- admin, role Administrator, `CDE Admin`, `admin@example.internal`
- recipient, role Recipient, `CDE Recipient`, `recipient@example.internal`

The recipient is the account that reads and routes submissions. The `@example.internal`
addresses are placeholders; a real deployment would use addresses that can receive mail.

## Email notifications

SMTP is left at the GlobaLeaks demo defaults (`mail.globaleaks.org`), so notification
emails are not actually delivered. The desk works without them, the recipient logs in to
see new submissions. Configuring a real SMTP server under Settings and Notification is
worth it only if email alerts to recipients are wanted.

## The onion address

The submission `.onion` address is generated on first run and stored in the volume at
`/var/globaleaks/files` alongside its private key. It is the discovery address submitters
use, and it cannot be regenerated to the same value: losing the key loses the address
permanently. A new clone generates a different `.onion`, which is the correct behaviour for
an independent instance. Backing up the volume preserves a given address; the key never
belongs in git.

## Restoring from a volume backup

Redoing the steps above is the clean path for a fresh, independent desk. Where an exact
copy is wanted instead, including the same `.onion`, the recipients, and any received
submissions, the alternative is to back up and restore the whole `globaleaks_globaleaks-data`
volume rather than reconfigure by hand. That backup carries secrets: the private onion key,
the encrypted database, and the keys tied to the admin password. It can be moved out of band
between trusted hosts, but it has no place in the repository.
