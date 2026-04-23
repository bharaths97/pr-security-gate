import java.io.InputStream;
import java.io.ObjectInputStream;

public class InsecureDeserialization {
    public Object load(InputStream stream) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(stream);
        return ois.readObject();
    }
}
