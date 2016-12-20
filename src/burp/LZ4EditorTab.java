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
import java.util.zip.GZIPOutputStream;

import net.jpountz.lz4.LZ4BlockInputStream;
import net.jpountz.lz4.LZ4BlockOutputStream;
import net.jpountz.lz4.LZ4Compressor;
import net.jpountz.lz4.LZ4Factory;
import net.jpountz.lz4.LZ4FastDecompressor;
import net.jpountz.lz4.LZ4SafeDecompressor;


/**
 * Uncompresses LZ4ped data for display in the message editor tab.
 * Compresses data in LZ4 format after manipulation.
 */
class LZ4EditorTab extends AbstractDecompressorEditorTab implements IMessageEditorTab {

	// public static final byte[] LZ4_MAGIC = {(byte) 0x18, (byte)0x4d, (byte)0x22, (byte) 0x04};
	
	// LZ4 Block Stream Magic Byte
	public static final byte[] LZ4_MAGIC  = {(byte)0x4c, (byte)0x5a , (byte)0x34, (byte)0x42, (byte)0x6c, (byte)0x6f, (byte)0x63, (byte)0x6b};

	public LZ4EditorTab(IMessageEditorController controller, IBurpExtenderCallbacks callbacks,
			IExtensionHelpers helpers, 	boolean editable) {
		super(controller, callbacks, helpers, editable);
	}


	public String getTabCaption() {
		return "LZ4 Data";
	}

	@Override
	protected boolean detect(byte[] content) {
		int bodyOffset = getHelpers().analyzeRequest(content).getBodyOffset();
		return getHelpers().indexOf(content, LZ4_MAGIC, true, bodyOffset, content.length) > -1;
	}

	@Override
	protected byte[] decompress(byte[] content) throws IOException {
		
		int bodyOffset = getHelpers().analyzeRequest(content).getBodyOffset();
		
		byte[] compressed = Arrays.copyOfRange(content, bodyOffset, content.length);
		ByteArrayInputStream bis = new ByteArrayInputStream(compressed);
		LZ4BlockInputStream is = new LZ4BlockInputStream(bis);
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		byte[] buffer = new byte[1024];
		int bytes_read;

		while ((bytes_read = is.read(buffer)) > 0) {
			baos.write(buffer, 0, bytes_read);
		}
		baos.close();
		is.close();
		return baos.toByteArray();
		
	}
	
	@Override
	protected byte[] compress(byte[] content) throws IOException {
		
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		LZ4BlockOutputStream os = new LZ4BlockOutputStream(baos);
		
		os.write(content);
		os.flush();
		os.close();
		baos.close();
		return baos.toByteArray();
			
	}

}
