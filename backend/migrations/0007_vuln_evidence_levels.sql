-- Poziomy dowodu podatności: oprócz potwierdzonej sondą i dokładnej wersji także wersja pakietu
-- dystrybucji (poprawka mogła zostać przeniesiona wstecz) i CVE warunkowe (wymaga innego komponentu).

ALTER TABLE vulnerabilities DROP CONSTRAINT vulnerabilities_evidence_check;
ALTER TABLE vulnerabilities ADD CONSTRAINT vulnerabilities_evidence_check
    CHECK (evidence IN ('confirmed', 'version_match', 'version_backport', 'version_conditional'));
