CREATE TRIGGER refresh_tokens_updated_at
    BEFORE UPDATE ON refresh_tokens
    FOR EACH ROW
    EXECUTE PROCEDURE update_updated_at_column();