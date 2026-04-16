-- Add financial verification flag for transit inventory preview and quick status updates.
ALTER TABLE logistics_in_transit
    ADD COLUMN financial_verified TINYINT(1) NOT NULL DEFAULT 0 AFTER qty_consistent;
