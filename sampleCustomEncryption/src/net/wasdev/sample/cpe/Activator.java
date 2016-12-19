package net.wasdev.sample.cpe;

import java.util.Dictionary;
import java.util.Hashtable;

import org.osgi.framework.BundleActivator;
import org.osgi.framework.BundleContext;
import org.osgi.framework.ServiceRegistration;

import com.ibm.wsspi.security.crypto.CustomPasswordEncryption;

public class Activator extends CustomEncryptionImpl implements BundleActivator {

    private ServiceRegistration<CustomPasswordEncryption> sr;
    private String CUSTOMENC_SERVICE_PID = "customEnc";
    private CustomPasswordEncryption custom_enc = new CustomEncryptionImpl();

    /*
     * (non-Javadoc)
     * @see org.osgi.framework.BundleActivator#start(org.osgi.framework.BundleContext)
     */
    public void start(BundleContext context) throws Exception {
        sr = context.registerService(CustomPasswordEncryption.class, custom_enc, getProps());
    }

    /*
     * (non-Javadoc)
     * @see org.osgi.framework.BundleActivator#stop(org.osgi.framework.BundleContext)
     */
    public void stop(BundleContext context) throws Exception {
        sr.unregister();
    }

    private Dictionary<String, String> getProps() {
        Dictionary<String, String> props = new Hashtable<String, String>();
        props.put(org.osgi.framework.Constants.SERVICE_PID, this.CUSTOMENC_SERVICE_PID);
        return props;
    }
}
