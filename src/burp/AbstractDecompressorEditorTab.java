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

import java.awt.Component;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Base class for decompressor editor tabs.
 */
public abstract class AbstractDecompressorEditorTab implements IMessageEditorTab {

	private static PrintStream stderr;
	private static PrintStream stdout;

	private IBurpExtenderCallbacks callbacks;
	private IExtensionHelpers helpers;
	private boolean editable;
	private ITextEditor textEditor;
	private byte[] currentMessage;


	public AbstractDecompressorEditorTab(IBurpExtenderCallbacks callbacks,
			IExtensionHelpers helpers, boolean editable) {

		this.callbacks = callbacks;
		this.helpers = helpers;
		this.editable = editable;

		this.textEditor = callbacks.createTextEditor();
	}

	/**
	 * Decompresses data from an HTTP request or response.
	 *
	 * @param compressedData	HTTP request or response containing the the compressed data
	 * 							(may include HTTP headers).
	 *
	 * @return 					the uncompressed HTTP body.
	 * @throws Exception		in case decompression failed.
	 */
	protected abstract byte[] decompress (byte[] compressedData) throws Exception;

	/**
	 * Compresses a data payload to be used as body of an HTTP request or response.
	 *
	 * @param decompressedData	Payload data, without HTTP headers.
	 * @return					the HTTP request or response, including headers.
	 * @throws Exception		in case compression failed.
	 */
	protected abstract byte[] compress (byte[] decompressedData) throws Exception;

	/**
	 * Returns whether a specific compression algorithm was detected.
	 *
	 * @param content			Analyze this content.
	 * @return					<code>true</code> if the compression algorith was applies.
	 */
	protected abstract boolean detect (byte[] content);


	@Override
	public byte[] getMessage() {
		byte[] message = this.currentMessage;

		// recompress the data unless it is unchanged
		if (textEditor.isTextModified()) {
			try {

				byte[] uncompressed = textEditor.getText();
				byte[] newBody = compress(uncompressed);
				helpers.buildHttpMessage(helpers.analyzeRequest(this.currentMessage).getHeaders(), newBody);

			} catch (Exception e) {
				Logger.getLogger(getClass().getName()).log(Level.SEVERE, null, e);
				textEditor.setText(helpers.stringToBytes("\n--- FAILURE ---\n\nSee output in extension tab for details"));
				BurpExtender._stderr.println(getStackTrace(e));
			}
		}

		return message;
	}

	@Override
	public boolean isEnabled(byte[] content, boolean isRequest) {
		return detect(content);
	}

	@Override
	public byte[] getSelectedData() {
		return textEditor.getSelectedText();
	}

	@Override
	public Component getUiComponent() {
		return textEditor.getComponent();
	}

	@Override
	public boolean isModified() {
		return textEditor.isTextModified();
	}

	@Override
	public void setMessage(byte[] content, boolean isRequest) {
		if (content == null) {
			// clear the editor
			textEditor.setText(null);
			textEditor.setEditable(false);
		} else {
			try {

				byte[] decompressed = null;
				if (detect(content)) {
					decompressed = decompress(content);
				}
				textEditor.setText(decompressed);

			} catch (Exception e) {
				Logger.getLogger(getClass().getName()).log(Level.SEVERE, null, e);
				textEditor.setText(helpers.stringToBytes("\n--- FAILURE ---\n\nSee output in extension tab for details"));
				BurpExtender._stderr.println(getStackTrace(e));
			}
			textEditor.setEditable(editable);
		}

		// remember the currently displayed content
		this.currentMessage = content;
	}

	protected boolean isEditable() {
		return editable;
	}

	protected void setEditable(boolean editable) {
		this.editable = editable;
	}

	protected byte[] getCurrentMessage() {
		return currentMessage;
	}

	protected void setCurrentMessage(byte[] currentMessage) {
		this.currentMessage = currentMessage;
	}

	protected IBurpExtenderCallbacks getCallbacks() {
		return callbacks;
	}

	protected IExtensionHelpers getHelpers() {
		return helpers;
	}

	protected ITextEditor getTextEditor() {
		return textEditor;
	}

	protected PrintStream getStderr() {
		if (stderr == null) {
			stderr = new PrintStream(callbacks.getStderr());
		}
		return stderr;
	}

	protected PrintStream getStdout() {
		if (stdout == null) {
			stdout = new PrintStream(callbacks.getStdout());
		}
		return stdout;
	}

	private static String getStackTrace(Throwable t) {
		StringWriter stringWritter = new StringWriter();
		PrintWriter printWritter = new PrintWriter(stringWritter, true);
		t.printStackTrace(printWritter);
		printWritter.flush();
		stringWritter.flush();

		return stringWritter.toString();
	}

}
