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
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

/**
 * Uncompresses gzipped data for display in the message editor tab.
 * Compresses data in gzip format after manipulation.
 */
class GzipEditorTab extends AbstractDecompressorEditorTab implements IMessageEditorTab {

	public static final byte[] GZIP_MAGIC = { (byte) 0x1f, (byte) 0x8b };


	public GzipEditorTab(IMessageEditorController controller, IBurpExtenderCallbacks callbacks,
			IExtensionHelpers helpers, 	boolean editable) {
		super(controller, callbacks, helpers, editable);
	}


	@Override
	public String getTabCaption() {
		return "GZip Data";
	}

	@Override
	protected boolean detect(byte[] content) {
		return getHelpers().indexOf(content, GZIP_MAGIC, false, 0, content.length) > -1;
	}


	@Override
	protected byte[] decompress(byte[] content) throws IOException {
		int gzipPos = getHelpers().indexOf(content, GZIP_MAGIC, false, 0, content.length);

		byte[] compressed = Arrays.copyOfRange(content, gzipPos, content.length);

		GZIPInputStream gzis = new GZIPInputStream(new ByteArrayInputStream(compressed));
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		byte[] buffer = new byte[1024];
		int bytes_read;

		while ((bytes_read = gzis.read(buffer)) > 0) {
			baos.write(buffer, 0, bytes_read);
		}
		baos.close();
		return baos.toByteArray();
	}

	@Override
	protected byte[] compress(byte[] content) throws IOException {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		GZIPOutputStream gzos = new GZIPOutputStream(baos);
		gzos.write(content);
		gzos.flush();
		gzos.close();
		baos.close();
		return baos.toByteArray();
	}

}
