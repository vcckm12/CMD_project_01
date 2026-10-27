-- Product details for the customer web (catalog look): brand, color, sizes, list price, rating, tags.
-- Display-only fields: carts and orders keep using price_krw, and the assistant's tools do not read them.
ALTER TABLE commerce.products
  ADD COLUMN brand varchar(60) NOT NULL DEFAULT '',
  ADD COLUMN color varchar(60) NOT NULL DEFAULT '',
  ADD COLUMN sizes varchar(120) NOT NULL DEFAULT '',
  ADD COLUMN material varchar(200) NOT NULL DEFAULT '',
  ADD COLUMN list_price_krw bigint CHECK (list_price_krw IS NULL OR list_price_krw >= 0),
  ADD COLUMN rating numeric(2,1) CHECK (rating IS NULL OR rating BETWEEN 0 AND 5),
  ADD COLUMN review_count integer NOT NULL DEFAULT 0 CHECK (review_count >= 0),
  ADD COLUMN tags varchar(60) NOT NULL DEFAULT '' CHECK (tags ~ '^[a-z,]*$');
