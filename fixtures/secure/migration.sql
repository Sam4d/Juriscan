ALTER TABLE private_profiles ENABLE ROW LEVEL SECURITY;
CREATE POLICY owner_records ON private_profiles USING (auth.uid() = owner_id);
