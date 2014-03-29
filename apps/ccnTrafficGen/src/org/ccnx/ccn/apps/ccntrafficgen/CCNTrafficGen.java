/*
 * A CCNx DRM producer program.
 *
 * Copyright (C) 2008, 2009 Palo Alto Research Center, Inc.
 *
 * This work is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License version 2 as published by the
 * Free Software Foundation.
 * This work is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details. You should have received a copy of the GNU General Public
 * License along with this program; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 */

// 1: ant run-trafficgen -DSRC /test1 -DDST /test2 -DTIME 2000 -DBYTES 2048 -DTT 30000 -DKICKSTART false
// 2: ant run-trafficgen -DSRC /test2 -DDST /test1 -DTIME 2000 -DBYTES 2048 -DTT 30000 -DKICKSTART true

package org.ccnx.ccn.apps.ccntrafficgen;

import java.util.concurrent.*;
import java.util.concurrent.atomic.*;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Random;
import java.util.Scanner;
import java.util.logging.Level;

import org.ccnx.ccn.io.CCNFileInputStream;
import org.ccnx.ccn.io.CCNInputStream;
import org.ccnx.ccn.utils.CommonParameters;
import org.ccnx.ccn.CCNContentHandler;
import org.ccnx.ccn.CCNFilterListener;
import org.ccnx.ccn.CCNHandle;
import org.ccnx.ccn.config.ConfigurationException;
import org.ccnx.ccn.impl.support.Log;
import org.ccnx.ccn.io.CCNFileOutputStream;
import org.ccnx.ccn.io.CCNOutputStream;
import org.ccnx.ccn.profiles.CommandMarker;
import org.ccnx.ccn.profiles.SegmentationProfile;
import org.ccnx.ccn.profiles.VersioningProfile;
import org.ccnx.ccn.profiles.metadata.MetadataProfile;
import org.ccnx.ccn.profiles.nameenum.NameEnumerationResponse;
import org.ccnx.ccn.profiles.nameenum.NameEnumerationResponse.NameEnumerationResponseMessage;
import org.ccnx.ccn.profiles.nameenum.NameEnumerationResponse.NameEnumerationResponseMessage.NameEnumerationResponseMessageObject;
import org.ccnx.ccn.profiles.security.KeyProfile;
import org.ccnx.ccn.protocol.CCNTime;
import org.ccnx.ccn.protocol.ContentName;
import org.ccnx.ccn.protocol.ContentObject;
import org.ccnx.ccn.protocol.Exclude;
import org.ccnx.ccn.protocol.ExcludeComponent;
import org.ccnx.ccn.protocol.Interest;
import org.ccnx.ccn.protocol.MalformedContentNameStringException;

/**
 * Stupidly simply class that sends data back and forth between two parties (possibly through a proxy such as ANDaNA)
 */
@SuppressWarnings("deprecation")
public class CCNTrafficGen implements CCNFilterListener 
{
	static int BUF_SIZE = 4096;	
	//protected boolean _finished = false;
	static AtomicBoolean _finished = new AtomicBoolean(false);
	protected CCNHandle netHandle;
	protected CCNHandle outHandle;
	private ContentName _responseName = null;
	private String srcURI;
	private String dstURI;
	protected ContentName srcPrefix; 
	protected ContentName dstPrefix;
	protected boolean readyToRequest = false;
	protected int maxInterarrivalTime = 1; // default
	protected int contentSize = 2048; // default

	// TODO: define variables to capture performance here
	// total bytes collected, RTT, avg RTT, etc etc
	public long elapsedRTT = 0L;
	public long numInterests = 0L;
	
	// "helpful" usage message
	public static void usage() {
		System.err.println("usage: ccnTrafficGen <ccn prefix URI> <kick start flag - first one to start sending?>");
	}

	public CCNTrafficGen(String srcURI, String dstURI, int maxInterarrivalTime, int contentSize, boolean kickStart) throws Exception {
		this.srcURI = new String(srcURI);
		this.dstURI = new String(dstURI);
		srcPrefix = ContentName.fromURI(srcURI);
		dstPrefix = ContentName.fromURI(dstURI);
		netHandle = CCNHandle.open(); // filter listener was deprecated...
		outHandle = CCNHandle.open(); // use a different network handle (socket) for reading data
		this.maxInterarrivalTime = maxInterarrivalTime;
		this.readyToRequest = kickStart;
		this.contentSize = contentSize;
		
		// set response name for NE requests
		_responseName = KeyProfile.keyName(null, netHandle.keyManager().getDefaultKeyID());
	}
	
	public void start() throws Exception 
	{
//		Log.info("Starting file proxy for " + _filePrefix + " on CCNx namespace " + _prefix + "...");
//		System.out.println("Starting file proxy for " + _filePrefix + " on CCNx namespace " + _prefix + "...");
		System.err.println("Starting Traffic Generator for: " + srcURI + ", " + dstURI);
		
		// All we have to do is say that we're listening on our main prefix.
		netHandle.registerFilter(srcPrefix, this);

		// If we're set to kick start... do so now!
//		if (kickStart)
//		{
//			readyToRequest = true;
////			System.err.println("We're kickstarting...");
////			if (requestContent() == false)
////			{
////				// DEAR LORD
////				throw new Exception("OH GAWD");
////			}
//		}
		
		// Start the new thread...
		new Thread()
		{
		    public void run() {
		    	Random r = new Random();
		    	while(_finished.get() == false)
		    	{
		    		try {
						Thread.sleep(r.nextInt(maxInterarrivalTime));
						if (readyToRequest && !_finished.get())
						{
							requestContent();
						}
					} catch (Exception e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					} // sleep for some random amount of time
		    	}
		    }
		}.start();
	}
	
	@SuppressWarnings("finally")
	public boolean handleInterest(Interest interest) {
		// Alright, we've gotten an interest. Either it's an interest for a stream we're
		// already reading, or it's a request for a new stream.
		Log.info("ccnTrafficGen main responder: got new interest: {0}", interest);
		System.err.println("Got interest: " + interest.toString());
		
		// IF we're not already sending data, make sure we do so now.
		readyToRequest = true;

		// Test to see if we need to respond to it.
		if (!srcPrefix.isPrefixOf(interest.name())) {
			System.err.println("Unexpected: got an interest not matching our prefix (which is " + srcPrefix + ")");
			return false;
		}

		// We see interests for all our segments, and the header. We want to only
		// handle interests for the first segment of a file, and not the first segment
		// of the header. Order tests so most common one (segments other than first, non-header)
		// fails first.
		if (SegmentationProfile.isSegment(interest.name()) && !SegmentationProfile.isFirstSegment(interest.name())) {
			System.err.println("Got an interest for something other than a first segment, ignoring {" + interest.name());
			return false;
		} else if (MetadataProfile.isHeader(interest.name())) {
			System.err.println("Got an interest for the first segment of the header, ignoring " + interest.name());
			return false;
		} 

		// Write/Request on demand
		try {
			boolean success = writeContent(interest);
			return success;
		} catch (Exception e) {
			// TODO Auto-generated catch block
			Log.warning("Exception occurred {0}: {1}: {2}", interest.name(), e.getClass().getName(), e.getMessage());
			System.err.println("Exception occurred: " + interest.name() + ", " + e.getClass().getName() + ", " + e.getMessage());
			e.printStackTrace();
		} finally {
			return false;
		}
	}
	
	protected byte[] fillRandomBytes(int n)
	{
		byte[] M = new byte[n];
		SecureRandom r = new SecureRandom();
		r.nextBytes(M);
		return M;
	}

	protected boolean requestContent() throws Exception 
	{
		// STEP 3: REQUEST ENCRYPTED MEDIA
		String contentName = dstURI + "/gen";
		ContentName argName = ContentName.fromURI(contentName);
		
		// stats
		numInterests++;
		long start = System.currentTimeMillis();
		
		System.err.println("Requesting content: " + contentName);
		CCNInputStream input = new CCNInputStream(argName, outHandle);
		
		System.err.println("UNVERSIONED? " + CommonParameters.unversioned);
		Log.info("UNVERSIONED? " + CommonParameters.unversioned);
		
		if (CommonParameters.timeout != null) {
			input.setTimeout(CommonParameters.timeout);
		}
		
		// Append the chunks of the content into a single blob
		int readsize = 1024;
//		Log.info("Consumer starting to read THE MOFO RANDOM DATA for the interest: " + argName.toString());
		byte[] buffer = new byte[readsize];
		ArrayList<byte[]> bytes = new ArrayList<byte[]>();
		int readcount = 0;
		while ((readcount = input.read(buffer)) != -1) {
			bytes.add(Arrays.copyOf(buffer, buffer.length));
		}
		
		// stats
		long end = System.currentTimeMillis();
		elapsedRTT += (end - start);
		
		System.err.println("Reassembling the bytes");
		byte[] blob = new byte[readsize * bytes.size()];
		int blockIndex = 0;
		for (int i = 0; i < bytes.size() && blockIndex < blob.length; i++)
		{
			byte[] block = bytes.get(i); 
			for (int j = 0; j < block.length && blockIndex < blob.length; j++)
			{
				blob[blockIndex++] = block[j];
			}
		}

		////////////////////////////////////////
		// TODO: process the blob if necessary
		////////////////////////////////////////

		return true;
	}
	
	protected boolean writeContent(Interest outstandingInterest) throws Exception 
	{
		ContentName meat = outstandingInterest.name().postfix(srcPrefix);
		String postfix = meat.toString();
		Log.info("Producer received interest: " + postfix);
		String command = meat.stringComponent(0);
		
		System.err.println("Producer sending random content back");
		byte[] M = fillRandomBytes(contentSize); // TODO: pick a better number of bytes here
		if (command.equals("gen")) 
		{
			// Create an output stream to send data back downstream to the consumer
			CCNOutputStream os = new CCNOutputStream(outstandingInterest.name(), netHandle);
			os.addOutstandingInterest(outstandingInterest);
		
			// Write the encrypted message contents and then quit
			os.write(M);
			os.flush();
			os.close();

			return true;
		}
		else
		{
			System.err.println("ASDASDASDASDA?!?!?!?!");
			return false;
		}
	}

    /**
     * Turn off everything.
     * @throws IOException 
     */
	public void shutdown() throws IOException {
		if (null != netHandle) {
			netHandle.unregisterFilter(srcPrefix, this);
			System.out.println("Shutting down traffic generator.");
		}
		_finished.set(true);
	}
	
	public boolean finished() { return _finished.get(); }

	/**
	 * @param args
	 */
	public static void main(String[] args) 
	{
		if (args.length != 6) 
		{
			usage();
			return;
		}
		
		// fetch parameters
		String srcURI = args[0];
		String dstURI = args[1];
		int maxInterarrivalTime = Integer.parseInt(args[2]);
		int contentSize = Integer.parseInt(args[3]);
		long totalTime = Long.parseLong(args[4]);
		Boolean kickStart = Boolean.parseBoolean(args[5]);

		System.err.println("src: " + srcURI);
		System.err.println("dst: " + dstURI);
		System.err.println("max interarrival time: " + maxInterarrivalTime);
		System.err.println("content size: " + contentSize + " bytes");
		System.err.println("experiment time: " + totalTime);
		System.err.println("start: " + kickStart);
		
		try {
			Log.setDefaultLevel(Level.WARNING);
			CCNTrafficGen generator = new CCNTrafficGen(srcURI, dstURI, maxInterarrivalTime, contentSize, kickStart);
			
			// All we need to do now is wait until interrupted.
			Scanner sin = new Scanner(System.in);
			generator.start();
			while (!generator.finished()) {
				// we really want to wait until someone ^C's us.
				try {
					Thread.sleep(totalTime);
					generator.shutdown();
				} catch (InterruptedException e) {
					// do nothing
				}
			}

			// Print stats..
			System.err.println("Done running - print stats now");
			long rtt = generator.elapsedRTT;
			long ni = generator.numInterests;
			System.out.println(rtt + "," + ni + "," + ((double)rtt / (double)ni));

			// force quit...
			System.exit(0); //
		} catch (Exception e) {
			Log.warning("Exception in ccnTrafficGen: type: " + e.getClass().getName() + ", message:  "+ e.getMessage());
			Log.warningStackTrace(e);
			System.err.println("Exception in ccnTrafficGen: type: " + e.getClass().getName() + ", message:  "+ e.getMessage());
			e.printStackTrace();
		}
	}
}
