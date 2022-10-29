package burp;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.GZIPOutputStream;
import java.util.zip.InflaterInputStream;

public class DeflateEditorTab extends AbstractDecompressorEditorTab implements IMessageEditorTab {

	public static final byte[] DEFLATE_MAGIC = { (byte) 0x78, (byte) 0x9c };

	public DeflateEditorTab(IMessageEditorController controller, IBurpExtenderCallbacks callbacks,
			IExtensionHelpers helpers, boolean editable) {
		super(controller, callbacks, helpers, editable);
	}

	@Override
	public String getTabCaption() {
		return "Deflate Data";
	}


	@Override
	public boolean detect (byte[] content) {
		int bodyOffset = getHelpers().analyzeRequest(content).getBodyOffset();
		return getHelpers().indexOf(content, DEFLATE_MAGIC, false, bodyOffset, content.length) > -1;
	}

	@Override
	protected byte[] decompress(byte[] content) throws IOException {
		int bodyOffset = getHelpers().analyzeRequest(content).getBodyOffset();

		byte[] compressed = Arrays.copyOfRange(content, bodyOffset, content.length);

		InflaterInputStream iis = new InflaterInputStream(new ByteArrayInputStream(compressed));
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		byte[] buffer = new byte[1024];
		int bytes_read;

		while ((bytes_read = iis.read(buffer)) > 0) {
			baos.write(buffer, 0, bytes_read);
		}
		baos.close();
		return baos.toByteArray();
	}

	@Override
	protected byte[] compress(byte[] content) throws IOException {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		DeflaterOutputStream dos = new DeflaterOutputStream(baos);
		GZIPOutputStream gzos = new GZIPOutputStream(baos);
		gzos.write(content);
		gzos.flush();
		gzos.close();
		baos.close();
		return baos.toByteArray();
	}

}
