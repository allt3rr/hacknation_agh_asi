-- Detekcje technologii jako jawny JSON (bez sekretów), żeby dashboard liczył w SQL bez deszyfrowania.
ALTER TABLE observations ADD COLUMN detections jsonb NOT NULL DEFAULT '[]';
