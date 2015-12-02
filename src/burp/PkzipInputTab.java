/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2015 Antoine Neuenschwander
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

package burp;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.zip.DataFormatException;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

public class PkzipInputTab extends AbstractDecompressorEditorTab implements IMessageEditorTab {

	public static final byte[] PKZIP_MAGIC = { (byte) 0x50, (byte) 0x4b, (byte) 0x03, (byte) 0x04 };
	
	/** current zipentry. */
	private String zipEntry = "";


	public PkzipInputTab(IMessageEditorController controller, IBurpExtenderCallbacks callbacks,
			IExtensionHelpers helpers, boolean editable) {
		super(controller, callbacks, helpers, editable);
	}


	@Override
	public String getTabCaption() {
		return "PKzip Data";
	}


	@Override
	public boolean detect (byte[] content) {
		int bodyOffset = getHelpers().analyzeRequest(content).getBodyOffset();
		return getHelpers().indexOf(content, PKZIP_MAGIC, false, bodyOffset, bodyOffset + PKZIP_MAGIC.length) > -1;
	}


	@Override
	protected byte[] decompress(byte[] content) throws IOException, DataFormatException {
		int bodyOffset = getHelpers().analyzeRequest(content).getBodyOffset();
		byte[] baCompressed = Arrays.copyOfRange(content, bodyOffset, content.length);

		ZipInputStream zis = new ZipInputStream(new ByteArrayInputStream(baCompressed));
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		byte[] buf = new byte[1024];
		int bytes_read;
		zipEntry = zis.getNextEntry().getName();
		while ((bytes_read = zis.read(buf)) > 0) {
			baos.write(buf, 0, bytes_read);
		}
		zis.closeEntry();
		zis.close();
		baos.close();
		return baos.toByteArray();
	}


	@Override
	protected byte[] compress(byte[] content) throws IOException {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		ZipOutputStream zos = new ZipOutputStream(baos);
		zos.putNextEntry(new ZipEntry(zipEntry));
		zos.write(content);
		zos.close();
		baos.close();
		return baos.toByteArray();
	}
}
