# Facts and applicability

Facts have `state: known | unknown | disputed` and an optional primitive or string-array value. A `known` fact must include a value. Input is schema-validated; unknown field names are rejected. Provided facts are user-supplied, not independently verified. “Known” describes the user's declaration, not the scanner's legal certainty.

The intake asks about entity location and role, intended/actual markets, audience, child direction, known minor users, personal/sensitive data, advertising, transfers, subscriptions, UGC, AI, industries, revenue, retention, rights and incidents. This is a starting point. It does not infer thresholds, legal bases, consent, contracts or actual user ages from code.

`juriscan_applicability` returns `unknown` for every legal candidate in this alpha, even when facts are supplied. This is deliberate: no legally reviewed effective-date/territorial/threshold predicates are shipped. Selecting EU does not prove GDPR applicability; selecting a health industry does not establish HIPAA covered-entity status. No absence of a catalog match means “not applicable.”

Industry composition unions sector and feature domains into a manual checklist. Archetypes describe product shape but do not currently alter obligations. Multi-sector interactions, conflicting laws, state/province/city duties, contractual standards, sanctions, taxes, licensing and professional duties need specialist research. `other` and unknown jurisdiction codes return explicit gaps. No combinatorial enumeration can ensure every possible business or law is covered.
