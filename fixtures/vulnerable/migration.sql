ALTER TABLE private_profiles DISABLE ROW LEVEL SECURITY;
CREATE POLICY open_records ON private_profiles USING (true);
