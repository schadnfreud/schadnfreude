window.convos={};
let SnippetBuffer = (function() {
	function SnippetBuffer() {
		this.ctx = new AudioContext();
		this.maxQueued = 42;
		this.snippets = [];
		this.playing = false;
		this.startTime = 0;
		this.lastSnippetOffset = 0;
	}
	SnippetBuffer.prototype.addSnippet = (data) =>  {
		if (this.snippets.length > this.maxQueued) {
			console.log('pboverflow');
			return; // buffalo overflow. Don't keep queuing so we can keep latency lower
		}
		let intar = new Int16Array(data)
		let buf = this.ctx.createBuffer(1, intar.length, 11025);
		let floatbuf = buf.getChannelData(0);
		for(let i = 0; i < intar.length; i++){
			floatbuf[i] = intar[i] * 1.0 / 0x7FFF; //convert 16bit to float
		}
		let snippet = this.ctx.createBufferSource();
		snippet.buffer = buf;
		snippet.connect(this.ctx.destination);
		let _this = this;
		snippet.onended = (e) => {
			_this.snippets.splice(_this.snippets.indexOf(snippet), 1);
			if (_this.snippets.length == 0) {
				console.log('pcmbuff stream starvation');
				_this.playing = false;
				_this.startTime = 0;
				_this.lastSnippetOffset = 0;
			}
		};
		if (this.playing) { //queue it
			snippet.start(this.startTime + this.lastSnippetOffset);
			this.lastSnippetOffset += snippet.buffer.duration;
			this.snippets.push(snippet);
		} else { // Start it!
			this.playing = true;
			this.snippets.push(snippet);
			this.startTime = this.ctx.currentTime;
			this.lastSnippetOffset = snippet.buffer.duration;
			snippet.start(this.startTime);
		}
	};
	return SnippetBuffer;
}());

function audioProcessFunc(sr, offs, sndbuf, cid){
	let stepsize = Math.max(Math.floor(sr / 11025), 1); //probably 4 if they're at 44 or 48khz
	let chunkoffset = 0;
	return (e) => {
		let dat = e.inputBuffer.getChannelData(0);
		for(let i=0;i<dat.length;i+=stepsize){
			offs = Math.floor(i * 11025 / sr) + chunkoffset;
			if(offs >= sndbuf.length){
				chunkoffset -= sndbuf.length;
				fetch('/audio', {
					method: 'POST',
					body: sndbuf.buffer,
					headers: {'cid':cid,'csrftoken': window.csrftok}
				});
			}
			offs = offs % sndbuf.length;
			sndbuf[offs]=dat[i]*0x7FFF;
		}
		chunkoffset = offs;
	};
}
function startCall(cid, nextfnc){
	if(window.aud){
		alertish('you are already in a call');
		return;
	}
	window.callcid = cid; //now we're live; pending is now real
	window.aud = new AudioContext({'latencyHint':'interactive'});
	navigator.mediaDevices.getUserMedia({'audio': true, 'video': false}).then((stream) => {
		acceptcall.style.display = 'none';
		callindicator.style.backgroundColor = 'lightgreen';
		callindicatortext.innerHTML = '📞 In call';
		callindicator.style.display = 'inline';
		window.audstream = stream;
		let sr = window.aud.sampleRate;
		console.log('Starting microphone stream; sample rate', sr);
		let proc = window.aud.createScriptProcessor(0, 1, 1); //buffer size up to the browser
		proc.onaudioprocess = audioProcessFunc(sr, 0, new Int16Array(512), cid);// 512 samples at 11khz; phone quality for about 0.05s
		window.aud.createMediaStreamSource(stream).connect(proc);
		proc.connect(window.aud.destination);
		nextfnc();
	}).catch((err) => {
		console.log(err);
		alertish('Audio error ' + err);
		delete window.aud;
	});
}
callbutton.addEventListener('click', () => {
	let chatting = document.getElementsByClassName('chatting');
	if(chatting.length === 0){
		alertish('Click on a contact to begin calling them');
		return;
	}
	let tgtKey = chatting[0].id;
	console.log('calling',chatting[0].getAttribute('name'));
	if(tgtKey.length > 0){//has convoid
		startCall(tgtKey, () => {});
	}else{ //get a convo then do the send
		newConvo(chatting[0].getAttribute('name')).then((cid)=>{
			startCall(cid, () => {});
		});
	}
});
proxbutton.addEventListener('click', (e) => {
	e.preventDefault();
	let version = document.querySelector('input[name="proxver"]:checked').value;
	if(proxy.value.length === 0 || proxy.value.indexOf(':') < 1){
		alertish('Enter a SOCKS server IP:Port');
		return;
	}
	fetch('/proxy', {
		method: 'POST',
		body: JSON.stringify({'proxy': proxy.value, 'ver': version}),
		headers: {'csrftoken': window.csrftok}
	}).then((rsp) => {window.close()});
});
//Find the best break points; where to add line/wrapping breaks to minimize the longest row len given a number of rows. 
//Try break after 1 img then find most even break points for 2+ and record longest section.
//Then try break after 2 img and find most even points for 3+ and record longest section.
//If longest after 2 was shorter or equal to after 1, then try again with 3, until one gets shorter. Then keep the last.
//Return the final longest row length. Doesn't actually need to return break points, flex'll figure that out anyway.
//Does return longest break length
function bestBreaks(startoffs, base_widths, num_breaks_left){
	if(num_breaks_left === 0){//recursion exit. num_breaks_left exhausted.
		let rowlen = 0;// We return the length of our row which is all our base widths added together.
		for(let i = startoffs; i < base_widths.length; i++){
			rowlen += base_widths[i];
		}
		return rowlen;
	}
	if(base_widths.length - startoffs <= 1){
		return base_widths[startoffs]; //recursion exit. If total - alreadyset = 1, then the best break is at the end
	}
	let beforebreaklen = 0; // the length of the first row
	let last_best_break = null; //ok fine
	for(let nextbreak = 1+startoffs; nextbreak < base_widths.length; nextbreak++){ //trying 1 first
		beforebreaklen += base_widths[nextbreak - 1];
		if(last_best_break !== null && beforebreaklen > last_best_break){ //the last break was better.
			break; //no need to calc bestBreaks again, our results will only be worse from here on out. Return the last break
		}
		let best_remaining_breaks = bestBreaks(nextbreak, base_widths, num_breaks_left - 1); // see what the other breaks are like by recursion
		if(last_best_break !== null && best_remaining_breaks > last_best_break){
			break; //the last break was better, just return it.
		}
		last_best_break = Math.max(best_remaining_breaks, beforebreaklen); //The longest break now is either our prefix (beforebreaklen) or the best of the rest (best_remaining_breaks)
	}
	return last_best_break; // final break was the best
}
function setVidSizes(){
	let pixratio = window.devicePixelRatio;
	let pixratiodHeight = (c) => Math.floor(c.getBoundingClientRect().height * pixratio) / pixratio;
	// "real" available height in CSS pixels = container height - controls height - callbar height - 20(callbar margin)
	let ch = pixratiodHeight(container) - pixratiodHeight(controls) - pixratiodHeight(callbar) - 20;
	// "real" available width in CSS pixels = messages width
	let cw = Math.floor(messages.getBoundingClientRect().width * pixratio) / pixratio;
	//We're going to figure out how big we can make each image by iterating on number of rows 1-N
	//This is kinda complicated, because some can be landscape, some portrait, etc. and we want to be nice to all.
	//It's made easier by deciding on a set number of rows rather than trying to figure out a tiling that will work by overlapping them.
	//For a given number of rows, the max row height is a simple calculation (available height / numrows)
	//So we then need to figure out how wide each image is, maintaining aspect ratio. This is simply naturalWidth/naturalHeight * rowHeight;
	//For this iteration, we bind each image by a square box. If an image's natural row scaled width is greater than the row height,
	//we just slap it with a maxWidth so it isn't.
	let fis=document.getElementsByClassName('fitvid');
	let comment = '';
	let lastRealHeight = null;
	let finalNumRows = 1;
	let lastRealWidth= null;
	let base_widths = [];
	for(let i = 0; i < fis.length; i++){
		let imgbasewidth = fis[i].videoWidth / fis[i].videoHeight;
		if(imgbasewidth > 1){
			imgbasewidth = 1; //chomp to square shape
		}
		base_widths.push(imgbasewidth); //save the base widths (how wide each img should be at 1 height)
	}
	for(let numrows = 1; numrows <= fis.length; numrows++){
		let rowheight = ch / numrows;
		comment+=' '+numrows+' rows, h '+rowheight;
		//Now find best break width
		let max_rowlen = bestBreaks(0, base_widths, numrows - 1) * rowheight; //line breaks = num rows - 1
		let realHeight = rowheight;
		if(max_rowlen > cw){
			realHeight = realHeight * cw / max_rowlen;
		}
		comment+=' rwl '+max_rowlen;
		if(lastRealHeight !== null && realHeight < lastRealHeight){
			break;
		}
		lastRealHeight = realHeight;
		lastRealWidth = (max_rowlen > cw ? realHeight : Math.floor(realHeight * cw / max_rowlen)); //we lied about the square box
		finalNumRows = numrows;
	}
	//Now set the calculated dimensions, height for imgs and width for containing divs (items)
	for(let i = 0; i < fis.length; i++){
		fis[i].style.maxHeight = Math.floor(lastRealHeight)+'px';
	}
	let itms=document.getElementsByClassName('item');
	for(let i = 0; i < itms.length; i++){
		itms[i].style.maxWidth = Math.floor(lastRealWidth)+'px';
	}
}
//Decodes a WEBM length/value byte
function decodeLength(byt, mask=true){
	let length = null;
	let valueMask = null;
	for(let n = 1; n < 9; n++){
		if((byt & ((1<<8) - (1<<(8 - n)))) == 1<<(8 - n)){
			length = n;
			valueMask = (1<<(8 - n)) - 1;
			break
		}
	}
	if(length === null){
		let msg = 'Bad WEBM lenval 0x'+byt.toString(16);
		console.log(msg);
		throw msg;
	}
	if(mask){
		byt = byt & valueMask;
	}
	return [length, byt];
}
//Pegs a WEBM size to make it undefined/unlimited. We do this so we can add stuff to clusters
function pegWebmSize(boff, u8view){
	console.log('pegging webm size at',boff);
	let length = decodeLength(u8view[boff])[0];
	u8view[boff] = (u8view[boff] | (1<<(8 - length)) - 1); //make size all 1's
	for(let i = 0; i < length - 1; i++){ //and the rest of size too
		boff += 1;
		u8view[boff] = 0xFF;
	}
}
//Reads a WEBM size field. Not pausable/resumable
function readWebmSize(parseState, u8view){
	let byt = u8view[parseState.offset];
	parseState.offset += 1;
	let lenSiz = decodeLength(byt);
	let length = lenSiz[0];
	let size = lenSiz[1];
	let origbyte = byt
	for(let i = 0; i < length - 1; i++){
		byt = u8view[parseState.offset];
		parseState.offset += 1;
		size = (size * 0x100) + byt;
	}
	if(size == Math.pow(2,7*length) - 1){//maximum size (0xFFFFFF...) means indeterminate
		size = null;
	}
	return size;
}
//Reads a WEBM ID; pausable/resumable in case an ID crosses received binary blobs
function readId(parseState, u8view){
	if(parseState.readingId === false){
		parseState.readingId = {i: 0, length: 0, id: 0};
		let byt = u8view[parseState.offset];
		parseState.offset+=1;
		let vlen = decodeLength(byt, false)
		parseState.readingId.length = vlen[0];
		if(parseState.readingId.length > 4){
			throw 'Cannot decode element ID with length > 4.';
		}
		parseState.readingId.id = byt;
	}else{
		console.log('RESUMING ID PARSE '+parseState.readingId.i+' OF '+parseState.readingId.length+' PARTIAL 0x'+parseState.readingId.id+' AT '+parseState.offset);
	}
	while (parseState.readingId.i < parseState.readingId.length - 1){
		if(u8view.length <= parseState.offset && parseState.readingId.i < parseState.readingId.length - 1){
			console.log('FREEZING ID PARSE '+parseState.readingId.i+' OF '+parseState.readingId.length+' PARTIAL '+parseState.readingId.id);
			return false;
		}
		let byt = u8view[parseState.offset];
		parseState.offset += 1;
		parseState.readingId.id = (parseState.readingId.id * 0x100) + byt;
		parseState.readingId.i++;
	}
	let id = parseState.readingId.id;
	parseState.readingId = false; //we're done
	return id;
}
//Parses a cluster element once we know the ID. Adjusts timecodes if needed & detects new clusters
function parseClusEl(parseState, u8view){
	let id = parseState.inid;
	let lastoffs = parseState.offset;
	let ctLen = readWebmSize(parseState, u8view);
	if(id == 0x1F43B675){
		pegWebmSize(lastoffs, u8view);
		parseState.inid = false;
		return;
	}
	let startOffs = parseState.offset;
	let nextOffs = parseState.offset + ctLen;
	if(id == 0xe7){
		let timecode = 0;
		for(let i = parseState.offset; i < parseState.offset + ctLen; i++){
			timecode *= 0x100;
			timecode += u8view[i];
		}
		let oldtime = timecode;
		console.log('Cluster timecode '+timecode+' vs lasto '+parseState.lasto+' tsadjust '+parseState.tsadjust+' ctLen '+ctLen+' parseState.offset '+parseState.offset);
		if (parseState.tsadjust != 0 && parseState.lasto > timecode - 50){ //close enough, leave it.
			console.log('TIME LAPSED. UNADJUSTING TIMESTAMPS CLUSTER');
		} else if (parseState.lasto < timecode + parseState.tsadjust - 60){ //fell back (lost a packet?)
			let clusadjust = parseState.lasto + 35 - timecode; //only 35 ms diff
			console.log('TIME GAP. ADJUSTING TIMESTAMPS', clusadjust);
			timecode += clusadjust;
		} else {
			timecode += parseState.tsadjust;
		}
		parseState.tsadjust = 0;
		parseState.clusto = timecode;
		if(oldtime !== timecode){
			for(let i = parseState.offset + ctLen - 1; i >= parseState.offset; i--){
				u8view[i] = (timecode & 0xFF);
				timecode = (timecode >> 8);
			}
		}
	}else if(id == 0xa3){
		let tracknum = readWebmSize(parseState, u8view);
		let tooff = parseState.offset;
		let timecode = u8view[parseState.offset] * 0x100;
		parseState.offset++;
		timecode += u8view[parseState.offset];
		parseState.offset++;
		let isKeyframe = ((u8view[parseState.offset] & 128) != 0);
		let unadjustedTotalTime = parseState.clusto + timecode;
		if(parseState.tsadjust != 0 && parseState.lasto > unadjustedTotalTime - 50){ //close enough, leave it.
			console.log('TIME LAPSED. UNADJUSTING TIMESTAMPS');
			parseState.tsadjust = 0;
		}else if(parseState.lasto < unadjustedTotalTime + parseState.tsadjust - 60){ //fell further back (lost another packet?)
			parseState.tsadjust = parseState.lasto + 35 - unadjustedTotalTime; //only 35 ms diff
			console.log('TIME GAP. ADJUSTING TIMESTAMPS', parseState.tsadjust);
		}
		if(parseState.tsadjust != 0){
			timecode += parseState.tsadjust;
			u8view[tooff] = Math.floor(timecode / 0x100);
			u8view[tooff+1] = timecode % 0x100;
			console.log('Adjusted timecode', timecode, 'Adjusted total', parseState.clusto + timecode,' offset ',tooff);
		}
		parseState.lasto = parseState.clusto + timecode; //lasto is last adjusted total offset
	}else{
		console.log('Unknown subclus ID 0x'+id.toString(16)+' len '+ctLen + ' pc '+parseState.postChunk);
		console.log('SimpleBlock body 0x'+startOffs.toString(16)+'-0x'+nextOffs.toString(16), 'lasto', parseState.lasto, 'tsadjust', parseState.tsadjust);
	}
	parseState.offset = nextOffs;
	parseState.inid = false;
}
//Usually just parses the id of the next cluster element
function parseClus(parseState, u8view){
	if(parseState.inid !== false){
		return; // we already parsed clus but not clusId
	}
	while(parseState.offset < u8view.length && (parseState.readingId !== false || parseState.postChunk === null
			|| (parseState.postChunk !== null && parseState.offset < parseState.postChunk))){
		parseState.inid = readId(parseState, u8view); //this could break in Chrome if the id spans received blobs
		if(parseState.inid === false
				|| parseState.offset === u8view.length || parseState.readingId !== false //this is where chrome chunks out
				|| parseState.inid !== 0xe7){ //skip timecodes, only pause on real data
			return;
		}
		parseClusEl(parseState, u8view);
	}
	parseState.inclus = (parseState.postChunk === null || parseState.offset < parseState.postChunk);
	return;
}
//Parses segment headers until it eats a cluster header, return the offset of the cluster length field
//This is right after the cluster ID, so you can then peg the size or paste on a new cluster body
//(even though we will have read the length field if possible and updated offset to be after the length)
function parseSeg(parseState, u8view){
	let lastoffs = parseState.offset;
	if(parseState.inclus && parseState.readingId === false){
		return lastoffs;// need to call parseClus first
	}
	while(parseState.offset < u8view.length){
		let id = readId(parseState, u8view);
		if(id === false){
			return lastoffs; // end of bytes while reading ID
		}
		lastoffs = parseState.offset;
		let elLen = readWebmSize(parseState, u8view);
		parseState.postChunk = (elLen === null ? null : parseState.offset + elLen);
		if(id == 0x1A45DFA3){
			console.log('WEBM: EBML start '+lastoffs+'-'+JSON.stringify(parseState.postChunk));
		}else if(id == 0x1549a966){
			console.log('WEBM: Info '+lastoffs+'-'+JSON.stringify(parseState.postChunk));
		}else if(id == 0x1654ae6b){
			console.log('WEBM: Tracks '+lastoffs+'-'+JSON.stringify(parseState.postChunk));
		}else if(id == 0x114d9b74){
			console.log('WEBM: SeekHead '+lastoffs+'-'+JSON.stringify(parseState.postChunk));
		}else if(id == 0x1F43B675){
			parseState.inclus = true;
			if(parseState.postChunk !== null){ //just ate a cluster opening
				pegWebmSize(lastoffs, u8view);//Peg it to undetermined size, so we don't worry about lost segments messing up cluster size
				parseState.postChunk = null;
			}
			break;// now you need to call parseClus again
		}else{
			console.log('WEBM: unknown id ' + id.toString(16));
			if(!id)
				break;
		}
		if(elLen === null){
			break;
		}
		parseState.offset = parseState.postChunk;
	}
	return lastoffs;
}
//Parses the header of a new WEBM file. Aborts if you've already parsed the WEBM headers
function parseWebmChunk(parseState, u8view){
	if(parseState.inseg){
		return;
	}
	if(0x1A45DFA3 != readId(parseState, u8view)){
		console.log('WEBM: fail. Not a webm video. Cannot parse.');
		throw 'WEBM: fail. Not a webm video. Cannot parse.';
	}
	let ebmlLen = readWebmSize(parseState, u8view);
	parseState.offset += ebmlLen; //skip ebml element
	let myId = readId(parseState, u8view);
	if(0x18538067 != myId){
		console.log('WEBM: fail. Not a segment element?',myId);
		throw 'WEBM: fail. Not a segment element?';
	}
	let segLen = readWebmSize(parseState, u8view);
	if(segLen !== null){
		console.log('WEBM: non-null segment len',segLen);
	}
	parseState.inseg = true;
}

function sendvChunks(sendable, cid, sid, packetNum, splits){
	fetch('video', {
		method: 'POST',
		body: sendable,
		headers: {'csrftoken': window.csrftok, 'cid': cid, 'sid': sid, 'p': packetNum, 'splits': splits.join(',')}
	});
}

function startVid(cid, screen) {
	console.log('startVid', screen, cid, window.callcid, window.incomingvideo);
	if(window.mediaRecorder){
		console.log('you are already sharing video');
		return;
	}
	if(screen && ! navigator.mediaDevices.getDisplayMedia){
		alertish('Your browser does not support screen sharing');
		return;
	}
	videoAcceptButton.disabled = true;
	let promise = null;
	if(screen){
		promise = navigator.mediaDevices.getDisplayMedia({video: {cursor: 'always'}});
	} else {
		promise = navigator.mediaDevices.getUserMedia({video: true});
	}
	promise.then((outgoingVideoStream) => {
		let videoBitsPerSecond = 32*1024*8; //32KBps video. TODO: configurable or negotiable?
		let sid = btoa(String.fromCharCode.apply(null, crypto.getRandomValues(new Uint8Array(8)))).replace(/\//g,"_").replace(/\+/g,"-").replace(/=/g,"");
		let packetNum = 0;
		let mediaRecorder = new MediaRecorder(outgoingVideoStream,{
			videoBitsPerSecond: videoBitsPerSecond,
			mimeType: 'video/webm\;codecs=vp8'
		});
		window.mediaRecorder = mediaRecorder; //make available.
		window.videoSid = sid;
		let localParseState = newParseState();
		window.firstvchunk = null;
		mediaRecorder.addEventListener('stop', () => { //User hit the stop button
			console.log('SENDING VIDSTOP '+sid);
			window.videoSid = null;
			fetch('vidstop', {method: 'POST', body: sid, headers: {'csrftoken': window.csrftok, 'cid': cid}});
		});
		mediaRecorder.addEventListener('dataavailable', (e) => {
			if(e.data.size < 1){
				return; // This sometimes happens because the poll rate is below the rate the lower layers send us chunks
			}
			//We don't just send immediately. Instead, we parse into sane digestible chunks to send to decrease overall latency
			let fileReader = new FileReader();
			fileReader.onload = (ev) => {
				if(window.videoSid === null){
					return;
				}
				let u8view = new Uint8Array(ev.target.result); // get the chunk as a byte array
				let splits = [];
				while(u8view.length > 0){
					if(localParseState.postChunk !== null)
						localParseState.postChunk -= localParseState.offset; //reset offsets
					localParseState.offset = 0;
					parseWebmChunk(localParseState, u8view); //parses outer container if present
					if(localParseState.inseg && ! localParseState.inclus){ //before cluster
						parseSeg(localParseState, u8view);
						if(window.firstvchunk === null && window.mediaRecorder === mediaRecorder){
							if(localParseState.inclus && localParseState.offset < u8view.length){
								parseClus(localParseState, u8view);//first video chunk; grab the timecode and start of next header
							} else if ( ! localParseState.inclus){ //in seg but not clus
								console.log('No cluster opening/timecode for first v chunk');
							} else {
								console.log('UNCLEAR VIDEO STATE', JSON.stringify(localParseState));
							}
							window.firstvchunk = u8view.slice(0,localParseState.offset);
							splits.push(window.firstvchunk); //queue it to send
							u8view = u8view.slice(localParseState.offset);
							continue;
						}
					}
					if(localParseState.inclus && localParseState.offset < u8view.length){
						while(true){
							if(localParseState.readingId === false && localParseState.inid !== false){
								parseClusEl(localParseState, u8view); //not us
							}
							parseClus(localParseState, u8view); //grab the next chunk ID if not already got
							if(localParseState.offset >= u8view.length || localParseState.offset > 1200){
								let sendable = u8view.slice(0,localParseState.offset);
								splits.push(sendable); //queue it to send
								u8view = u8view.slice(localParseState.offset);
								break;
							}
						}
					}
					if(window.firstvchunk === null && window.mediaRecorder === mediaRecorder){
						window.firstvchunk = ev.target.result; //test that the same mediaRecorder is not stopped
					}
				}
				let splitLengths = splits.map((s) => s.length); //calculate all the split lengths
				sendvChunks(new Blob(splits), cid, sid, packetNum, splitLengths);//then send all the chunks at once
				packetNum += splits.length;
			};
			fileReader.readAsArrayBuffer(e.data);
		});
		console.log('Starting recording');
		mediaRecorder.start(200); //200ms per chunk - note that browsers seem to give 1s per chunk instead
		callindicator.style.display='inline';
		localVideo.style.display = 'block';
		localVideo.classList.add('fitvid');
		localVideo.srcObject = outgoingVideoStream; //so we can see ourselves. Come see how good we look!
	}).catch((err) => {
		console.log('Video failure', err);
		videoAcceptButton.disabled = false;
		window.mediaRecorder = null;
		window.firstvchunk = null;
	});
}
localVideo.addEventListener('loadedmetadata', (event) => {console.log('video loaded');});
vidbutton.addEventListener('click', () => {
	let chatting = document.getElementsByClassName('chatting');
	if(chatting.length === 0){
		alertish('Click on a contact to begin calling them');
		return;
	}
	let tgtKey = chatting[0].id;
	console.log('vidcalling',chatting[0].getAttribute('name'));
	if(tgtKey.length > 0){//has convoid
		startVid(tgtKey, false);
	}else{ //get a convo then do the send
		newConvo(chatting[0].getAttribute('name')).then((cid)=>{
			window.callcid = cid;
			startVid(cid, false);
		});
	}
});
videoAcceptButton.addEventListener('click', () => {
	console.log('Video accept', window.callcid, window.pendingcallcid);
	if(window.callcid){
		startVid(window.callcid, false);
	} else if(window.pendingcallcid){
		window.callcid = window.pendingcallcid;
		startVid(window.pendingcallcid, false);
	}
});
screenbutton.addEventListener('click', () => {
	let chatting = document.getElementsByClassName('chatting');
	if(chatting.length === 0){
		alertish('Click on a contact to begin sharing a screen with them');
		return;
	}
	let tgtKey = chatting[0].id;
	console.log('Screen share with',chatting[0].getAttribute('name'));
	if(tgtKey.length > 0){//has convoid
		startVid(tgtKey, true);
	}else{ //get a convo then do the send
		newConvo(chatting[0].getAttribute('name')).then((cid)=>{
			window.callcid = cid;
			startVid(cid, true);
		});
	}
});
function stopCall(){
	console.log('Ending call.');
	if(window.aud){
		window.aud.close(); //this works on chrome
		delete window.aud;
	}
	if(window.audstream){
		window.audstream.getTracks().forEach((trk) => {
			console.log('Stopping Microphone stream', trk);
			trk.stop(); //this works on ffox
		});
	}
	//stop video stuff
	if(localVideo.srcObject && localVideo.srcObject.getTracks().length > 0){
		localVideo.srcObject.getTracks()[0].stop(); //stop the actual camera
		localVideo.srcObject = null;
	}
	if(window.mediaRecorder){
		window.mediaRecorder.stop();
		window.mediaRecorder = null;
	}
	window.firstvchunk = null;
	//fix up UI
	localVideo.style.display = 'none';
	localVideo.classList.remove('fitvid');
	let rvids = Object.keys(window.incomingvidstreams);
	for(let i = 0; i < rvids.length; i++){
		stopVid(rvids[i]);
	}
	acceptcall.style.display = '';
	callindicator.style.backgroundColor = 'lightblue';
	callindicatortext.innerHTML = 'Incoming call 📱';
	callindicator.style.display = 'none';
	window.hungups[window.callcid] = new Date().getTime(); //ignore future sound/video from this call
	window.hungups[window.pendingcallcid] = new Date().getTime(); //ignore future sound/video from this call
	window.callcid = null; //no longer in call
	window.pendingcallcid = null;
	window.callsdp = null;
}

function displayMsg(message, ours, fro, cid, seq){
	console.log('displayMsg', message, ours, fro, cid, seq);
	if(document.getElementById(cid+'.'+seq) !== null)
		return; //already exists
	if(!('text' in message) && !('fid' in message) && !('lve' in message) && !('ent' in message) && !('invitecid' in message) || ('type' in message && message['type'] == 'fold'))
		return;
	let msgwindow = document.createElement('p');
	msgwindow.className = 'roundedmsg' + (ours ? ' rightmsg' : '')
			+ (ours === null ? ' systemmsg' : '')
			+ ((typeof seq === 'string' && seq.length > 30) ? ' pending' : '');
	let dat = new Date(message['timestamp']);
	let m = dat.getMonth()+1;
	let day = dat.getDate();
	let hrs = dat.getHours();
	let mins = dat.getMinutes();
	let d = dat.getFullYear() + '-' + (m < 10 ? '0' : '') + m + '-' + (day < 10 ? '0' : '') + day
		+ ' ' + (hrs < 10 ? '0' : '') + hrs + ':' + (mins < 10 ? '0' : '') + mins;
	msgwindow.setAttribute('tstamp', message['timestamp']);
	msgwindow.setAttribute('id', cid+'.'+seq);
	if('dname' in message){
		addContact(fro, message['dname'], null);
	}
	if(!ours){
		let name = document.createElement('strong');
		name.appendChild(document.createTextNode(displayName(fro)));
		msgwindow.appendChild(name);
		msgwindow.appendChild(document.createElement('br'));
	}
	if('lve' in message){
		msgwindow.appendChild(document.createTextNode(displayName(message['lve']) + ' left the conversation'));
	}else if('ent' in message){
		msgwindow.appendChild(document.createTextNode(displayName(message['ent']) + ' joined the conversation'));
	}else if('text' in message){
		if(fro in window.displayNames && 'dname' in message && window.displayNames[fro].name !== message['dname']){
			//display name change
			let unt = document.createElement('a');
			unt.href = '#';
			unt.addEventListener('click', truster(fro, message['dname']));
			unt.appendChild(document.createTextNode(message['dname']));
			let msgtxt = window.displayNames[fro].verified && message['timestamp'] / 1000 > window.displayNames[fro].verified ? 'changed display name to ' : 'announced display name '
			msgwindow.appendChild(document.createTextNode(msgtxt));
			msgwindow.appendChild(unt);
		} else {
			let displayable = (message['text'].length===0 ? 'joined the conversation' : message['text']);
			msgwindow.appendChild(document.createTextNode(displayable));
		}
	} else {
		let a = document.createElement('a');
		if('invitecid' in message){
			a.setAttribute('href','#');
			a.addEventListener('click', accepter(fro, message)); //clicking will accept the invite
			let convel = document.getElementById(tob64(message['invitecid']));
			a.appendChild(document.createTextNode('Invite to join group conversation ' 
				+ (convel ? 'with ' + convel.innerText : tob64(message['invitecid']).substr(0,8)) )); //display name/initials shown for sender; cid shown for receipient who doesn't know members yet
		} else {
			a.setAttribute('href', '/download?'+cid+'.'+message['fid']);
			a.setAttribute('download', message['path']);
			let extension = message['path'].substr(message['path'].lastIndexOf('.')+1);
			if(['png','gif','jpg','jpeg','bmp'].indexOf(extension) >= 0){
				let imj = new Image();
				imj.src = '/download?'+cid+'.'+message['fid'];
				imj.style.maxWidth = '100%';
				imj.style.maxHeight = '50vh';
				a.appendChild(imj);
			}else{
				a.appendChild(document.createTextNode('File ' + message['path']));
			}
		}
		msgwindow.appendChild(a);
	}
	msgwindow.appendChild(document.createElement('br'))
	let time = document.createElement('span');
	time.classList.add('timestamp');
	time.appendChild(document.createTextNode(d))
	msgwindow.appendChild(time);
	let cldn = messages.childNodes;
	let ts = parseFloat(message['timestamp']);
	if (cldn.length == 0){
		messages.appendChild(msgwindow);
	}else if (ts < parseFloat(cldn[0].getAttribute('tstamp'))){
		messages.insertBefore(msgwindow, cldn[0]);
	} else {
		for(let i = cldn.length - 1; i >= 0; i--){
			if(ts >= parseFloat(cldn[i].getAttribute('tstamp'))){
				cldn[i].insertAdjacentElement('afterend', msgwindow);
				break;
			}
		}
	}
}
function logchat(cid, msg, ours, fro, s){
	if(!(cid in window.savedchats)){
		window.savedchats[cid] = {chats:[],seqs:new Set()};
	}
	let sc = window.savedchats[cid];
	let conv = window.convos[cid];
	let parts = {};
	if(cid in window.convos){
		if(!(fro in conv['participants']) && fro !== window.jr['mykey']){ //somebody got added
			refreshconvos(); //not a 1-1 convo anymore
		}
		parts = conv['participants'];
	}else{
		console.log('No cid in convos?', cid, msg, ours, fro, s);
		refreshconvos();
	}
	if(s !== null && !sc.seqs.has(s)){
		sc.chats.push(new Chat(fro, msg, ours, s));
		sc.seqs.add(s);
	}
	if('fid' in msg){
		let lock = 'shared' in msg && !msg['shared'];
		addFile({'id':msg['fid'],'met':msg,'lock':lock,'deleted':('deleted' in msg && msg['deleted'])},cid);
		if(!lock){
			if(shared.style.display !== 'flex'){
				showshare.style.fontSize = '200%';
				showshare.style.fontWeight = 'bold';
			}
			return;
		}
	}
	if(Object.keys(parts).length == 1 && window.jr['mykey'] in parts){
		return; //ignore self-sync convo; don't display it
	}
	if(s !== null){
		displayMsg(msg, ours, fro, cid, s);
	}
}

//really send the msg
window.pending={};
function pendMsg(msg, cid, hsh){
	if(hsh in window.pending){ //ack arrived before message send completed!
		let seq = window.pending[hsh];
		window.pending[hsh] = msg;
		ackMsg(hsh, cid, seq);
	} else {
		displayMsg(msg, true, false, cid, hsh);
		window.pending[hsh] = msg;
	}
}

async function convoMsg(cid, txt){
	console.log('convoMsg', cid, txt);
	let resp = await fetch('/sendmsg', {
		method: 'POST',
		body: JSON.stringify({'cid':cid,'text':txt}),
		headers: {'csrftoken': window.csrftok}
	});
	let rtext = await resp.text();
	if(resp.ok){
		let msg={'text':txt,'timestamp':(new Date()).getTime()};
		console.log(rtext);
		pendMsg(msg, cid, rtext);
		messages.scrollTop = messages.scrollTopMax;
	}else{
		console.log(resp, rtext);
		alertish(rtext);
	}
}

//starts a convo then sends a msg
async function newConvo(tgtk){
	let bod = JSON.stringify({'tgt':tgtk});
	let r = await fetch('/startconvo', {method: 'POST', body: bod, headers: {'csrftoken': window.csrftok}});
	if(r.ok){
		let res = await r.json();
		if('convoid' in res){
			console.log('Opened conn');
			window.convos[res['convoid']] = {'participants':{}};
			window.convos[res['convoid']]['participants'][tgtk]=1;
			addContact(tgtk, res['disp'], res['verified'] ); //update or create contact name
			let e = document.getElementsByName(tgtk)[0];
			e.setAttribute('id',res['convoid']); //set cid
			return res['convoid'];
		}
	}else{
		let txt = await r.text();
		alertish("Error opening conversation:\n" + txt);
		throw r;
	}
}
function sendMsg(){
	let chatting = document.getElementsByClassName('chatting');
	if(chatting.length === 0){
		alertish('Click on a contact to begin chatting with them');
		return;
	}
	let messagetext = messageinp.value;
	if(messagetext.length === 0){
		alertish('type something to send');
		return;
	}
	let tgtKey = chatting[0].id;
	console.log('sending '+messagetext+' to '+chatting[0].getAttribute('name'));
	if(tgtKey.length > 0){//has convoid
		convoMsg(tgtKey, messagetext);
		messageinp.value = '';
	}else{ //get a convo then do the send
		newConvo(chatting[0].getAttribute('name')).then((cid) => {
			convoMsg(cid, messageinp.value);
			messageinp.value='';
		});
	}
}
sendbutton.addEventListener('click', sendMsg);

async function newContact(ckey, cname, verified){
	let res = await fetch('/contacts', {
		method: 'POST',
		body: JSON.stringify({'ct':ckey, 'name':cname, 'good':''+(verified !== null)}),
		headers: {'csrftoken': window.csrftok}
	});
	let responseText = await res.text();
	if(responseText === 'ok'){
		addContact(ckey, cname, verified);
		clickContact(document.getElementsByName(ckey)[0]);
	}else{
		alertish(responseText);
	}
}

addcontactbutton.addEventListener('click', () => {
	newConvo(contactkey.value);
	contactmodal.style.display='none';
	container.style.display='flex';
});
function scanqr(){
	let video = document.createElement('video');
	let canvasElement = qrCanvas;
	let canvas = canvasElement.getContext('2d');
	let outputData = document.getElementById('outputData');

	// Use facingMode: environment to attemt to get the front camera on phones
	navigator.mediaDevices.getUserMedia({ 'video': { 'facingMode': 'environment' } }).then((stream) =>  {
		video.srcObject = stream;
		video.setAttribute('playsinline', true); // required to tell iOS safari we don't want fullscreen
		video.play();
		requestAnimationFrame(tick);
		qrdonebutton.addEventListener('click', stopqr);
		
	});
	function stopqr(){
		video.srcObject.getTracks().forEach((trk) => {
			console.log('Stopping QR stream', trk);
			trk.stop();
		});
		qrdonebutton.removeEventListener('click', stopqr);
	}
	function tick() {
		if (video.readyState === video.HAVE_ENOUGH_DATA) {
			canvasElement.hidden = false;
			canvasElement.height = video.videoHeight;
			canvasElement.width = video.videoWidth;
			canvas.drawImage(video, 0, 0, canvasElement.width, canvasElement.height);
			let imageData = canvas.getImageData(0, 0, canvasElement.width, canvasElement.height);
			let code = window['jsQR'](imageData.data, imageData.width, imageData.height, { 'inversionAttempts': 'dontInvert' });
			if (code && code.data.length >= 47 && code.data.startsWith('sf:')){
				newConvo(code.data.substr(3, 44)).then((c)=>{
					console.log('Reached contact meet from QR!');
					contactmodal.style.display='none';
					container.style.display='flex';
				});
				console.log('Adding contact from QR...');
				stopqr();
				return; //Done grabbing the video
			}
		}
		requestAnimationFrame(tick);
	}
}
scanqrbutton.addEventListener('click', () => {
	if(window['jsQR']){
		scanqr();
	}else{
		let qrscript = document.createElement('script');
		qrscript.addEventListener('load', () => {
			scanqr();
		});
		qrscript.src = '/jsQR.js';
		document.head.appendChild(qrscript);
		bootstrap(); //ok, restart everything now that we should be running
	}
});
qrdonebutton.addEventListener('click', () => {
	container.style.display='flex';
	contactmodal.style.display='none';
});

//invite cid to join scid
async function invite(cid,scid){
	let res = await fetch('/sendinvite', {
		method: 'POST',
		body: JSON.stringify({'cid':cid,'scid':scid}),
		headers: {'csrftoken': window.csrftok}
	});
	let txt = await res.text();
	console.log(txt);
	if(res.ok){
		let str = atob(scid);
		let bytes = [];
		for (let i = 0; i < str.length; ++i){
			bytes.push(str.charCodeAt(i));
		}
		let msg={'invitecid':bytes,'meetkey':[],'sesskey':[],'meetaddr':[],'timestamp':(new Date()).getTime()};
		pendMsg(msg, cid, txt);
	}else{
		alertish(txt);
	}
}
function inviter(cid,scid){
	return () => {
		demodal();
		invite(cid,scid);
	}
}
function cidinviter(n, scid){
	return () => {
		newConvo(n).then((cid)=>{
			demodal();
			invite(cid,scid);
		})
	}
}

//Remove all child nodes
function rmrf(el){
	while(el.childNodes.length > 0){
		el.removeChild(el.childNodes[0]);
	}
}
function displayName(pubkey){
	if(pubkey == "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA") return "[system message]";
	if(!window.displayNames || !(pubkey in window.displayNames)){
		return pubkey;
	}
	return (window.displayNames[pubkey].verified ? '' : '(UNVERIFIED) ') + window.displayNames[pubkey].name;
}
function doinvite(){
	let chattin = document.getElementsByClassName('chatting');
	if(chattin.length === 0){
		alertish('Select a conversation to invite a contact to');
		return;
	}
	if(!chattin[0].hasAttribute('id')){ //start a convo then invite
		newConvo(chattin[0].getAttribute('name')).then(doinvite);
		return;
	}
	rmrf(popuplist);
	let ctx = document.getElementsByClassName('contact');
	for(let i=0; i<ctx.length; i++){
		if(ctx[i].hasAttribute('name')){
			let n = ctx[i].getAttribute('name');
			if(n != chattin[0].getAttribute('name')){
				let b=document.createElement('button');
				b.appendChild(document.createTextNode(displayName(n)));
				let cid=ctx[i].getAttribute('id');
				let scid=chattin[0].getAttribute('id');
				b.addEventListener('click', cid ? inviter(cid,scid) : cidinviter(n, scid));
				popuplist.append(b);
			}
		}
	}
	if(popuplist.childNodes.length == 0){
		alertish("No other contacts to invite. Meet some new people!");
		return;
	}
	showpop('Cancel');
}
invitebutton.addEventListener('click', doinvite);
async function do_invites(invite_list, scid, idx){
	demodal();
	let fails = [];
	for(let i = idx; i < invite_list.length; i++){
		let nam_and_cid = invite_list[i];
		try {
			if(!nam_and_cid[1]){
				nam_and_cid[1] = await newConvo(nam_and_cid[0]);
			}
			await invite(nam_and_cid[1], scid);
		} catch(e) {
			console.log("error inviting",nam_and_cid,e);
			fails.push(nam_and_cid[0]);
			continue;
		}
	}
	return fails;
}
async function dogroup(){
	rmrf(popuplist);
	let ctx = document.getElementsByClassName('contact');
	for(let i=0; i<ctx.length; i++){
		if(ctx[i].hasAttribute('name')){
			let n = ctx[i].getAttribute('name');
			let inp=document.createElement('input');
			inp.setAttribute('type', 'checkbox');
			inp.setAttribute('id', n+'_chk');
			popuplist.append(inp);
			inp.value = n;
			inp.cid = ctx[i].getAttribute('id');
			let lab=document.createElement('label');
			lab.appendChild(document.createTextNode(displayName(n)));
			lab.setAttribute('for', n+'_chk');
			popuplist.append(lab);
		}
	}
	if(popuplist.childNodes.length == 0){
		alertish("No contacts to invite. Meet some new people!");
		return;
	}
	let b=document.createElement('button');
	b.appendChild(document.createTextNode('Start group'));
	b.addEventListener('click', async ()=>{
		let inps = popuplist.getElementsByTagName('input');
		let vals = [];
		for(let i = 0; i < inps.length; i++){
			if(inps[i].checked){
				vals.push([inps[i].value, inps[i].cid]);
			}
		}
		if(vals.length == 0){
			alertish("No contacts selected for group");
			return;
		}
		//repeatedly try until the new convo works
		let fails = [];
		while(vals.length > 0) {
			let cid;
			try {
				cid = await newConvo(vals[0][0]);
			} catch(e) {
				fails.push(vals.shift()[0]);
				continue;
			}
			fails = fails.concat(await do_invites(vals, cid, 1));
			break;
		}
		if(fails.length > 0){
			alertish("Failed to reach the following:\n" + fails.map(displayName).join("\n"));
		}
	});
	popuplist.append(b);
	showpop('Cancel');
}
groupbutton.addEventListener('click', dogroup);

async function confirmish(myMessage) {
	rmrf(popuplist);
	popuplist.appendChild(document.createTextNode(myMessage));
	let okButton = document.createElement('button');
	okButton.appendChild(document.createTextNode('Ok'));
	popuplist.appendChild(okButton);
	return new Promise((complete)=>{
		let res = false;
		let completer = () => {complete(res); demodal(); overlay.removeEventListener('click', completer);};
		okButton.addEventListener('click', (e) => {res = true; completer()}); //on OK return true
		showpop('Cancel').addEventListener('click', completer); //on cancel return false
		overlay.addEventListener('click', completer); //cancel if they click outside the box too
	});
}
function alertish(myMessage) {
	rmrf(popuplist);
	popuplist.appendChild(document.createTextNode(myMessage));
	showpop('Ok');
}
function showpop(closeMessage) {
	let b = document.createElement('button');
	b.appendChild(document.createTextNode(closeMessage));
	b.addEventListener('click', demodal);
	popuplist.appendChild(b);
	overlay.style.display = 'block';
	popuplist.style.display = 'flex';
	return b;
}
function demodal(){
	let mods=document.getElementsByClassName('modal');
	for(let i=0;i<mods.length;i++){
		mods[i].style.display='none';
	}
	rmrf(popuplist);
}
overlay.addEventListener('click', demodal);

window.savedchats = {};
/** @constructor */
function Chat(fro, msg, ours, seq) {
  this.fro = fro;
  this.msg = msg;
  this.ours = ours;
  this.seq = seq;
}
function clickContact(el){
	if(!el){
		return;
	}
	contacts.classList.add('blockdesk');
	chatwindow.classList.remove('hidmobl');
	chatwindow.style.display='flex';
	if(el.classList.contains('chatting')){
		return;
	}
	selectContact(el);
}
//Clear all messages
function clearChatUi(){
	chatwindow.style.display='flex';
	let ctx = document.getElementsByClassName('contact');
	for (let i = 0; i < ctx.length; i++){
		ctx[i].classList.remove('chatting');
	}
	rmrf(messages);
	rmrf(sentfolder);
	rmrf(sharedfolder);
	if(shared.style.display == 'flex'){ //visible
		showshared();
	}
}
function selectContact(el){
	clearChatUi();
	el.classList.add('chatting');
	let cid = el.getAttribute('id');
	if(!cid)
		return; //haven't started chatting yet
	//Display all messages
	if(cid in window.savedchats){
		let cs = window.savedchats[cid].chats;
		for(let i = 0; i < cs.length; i++){
			let f = cs[i].fro;
			if(el.hasAttribute('name') && f != el.getAttribute('name') && f != window.jr['mykey']){ //not a 1-1 convo anymore
				el.removeEventListener('click', window.names[el.getAttribute('name')]);
				el.addEventListener('click', idClick(cid));
				el.removeAttribute('name');
			}
			if(cs[i].ours === null && el.innerText.indexOf(f) === -1){
				el.appendChild(document.createTextNode(' '+f));
			}
			displayMsg(cs[i].msg, cs[i].ours, f, cid, cs[i].seq);
		}
		messages.scrollTop = messages.scrollTopMax;
	}else{
		window.savedchats[cid] = {chats:[],seqs:new Set()};
		fetch('/msghistory?'+cid);//We Can Remember It for You Wholesale
	}
	let num_participants = Object.keys(window.convos[cid]['participants']).length;
	invitebutton.style.display = num_participants == 1 ? 'none' : 'block'; //don't invite to 1-1
}

function nameClick(n){
	return () => { console.log('selecting',n);clickContact(document.getElementsByName(n)[0]);};
}

function idClick(i){
	return () => { console.log('selecting',i);clickContact(document.getElementById(i));};
}
function initials(k, nameinfo){
	let kname = nameinfo[0];
	let trusted = nameinfo[1];
	let parts = kname.trim().split(' ');
	let prefix = trusted ? '' : '?';
	if(parts.length == 0 || parts[0].length == 0){
		return prefix + k.substr(0,2);
	}else if(parts.length == 1 || parts[parts.length - 1].length == 0){
		return prefix + parts[0].substr(0,1);
	}
	return prefix + parts[0].substr(0,1) + parts[parts.length - 1].substr(0,1);
}
//assumes it's a known convo; adds initials
function updateConvoText(contnewel, participants){
	rmrf(contnewel);
	contnewel.removeAttribute('name');
	for(let part in participants){
		contnewel.appendChild(document.createTextNode(initials(part, participants[part])+' '));
		if(participants[part][0].length > 0)
			addContact(part, participants[part][0], participants[part][1] ? new Date().getTime() / 1000 : null); //make sure they're in the contact list
	}
	//{'aZqp4': ['bob',true], 'iJ87z': ['alice',false]}  =>  "bob - aZqp4 \n alice - iJ87z"
	contnewel.setAttribute('title', Object.entries(participants).map((e) => {return [e[1][0], e[0]].join(' - ')}).join('\n'));
}
//Creates convo DOM. Assumes there is > 1 participant
function addConvo(cid, participants){
	console.log('agc',cid,participants);
	let contnewel = document.createElement('p');
	contnewel.className = 'contact';
	contnewel.setAttribute('id', cid);
	contnewel.addEventListener('click', idClick(cid));
	updateConvoText(contnewel, participants);
	contacts.appendChild(contnewel);
}

function ensureConvoDisplay(k, parts){
	console.log('ecd', k, "parts", parts, "dge", document.getElementById(k));
	let el=document.getElementById(k);
	let numparts = Object.keys(parts).length;
	if(!el){//not in there yet?
		if(numparts == 1){
			let dmid = Object.keys(parts)[0];
			let dmname = parts[dmid];
			let contact = document.getElementsByName(dmid);
			if(contact.length > 0 && contact[0].hasAttribute('id')) {
				addConvo(k, parts); //Duplicate contact convo. Just add a new one
			} else {
				addContact(dmid, dmname[0], dmname[1] ? new Date().getTime() / 1000 : null);
				document.getElementsByName(dmid)[0].setAttribute('id',k);
			}
		} else if(numparts > 1){ //group convo
			addConvo(k, window.convos[k]['participants']);
		}
	} else {
		if(numparts == 1){
			let dmid = Object.keys(parts)[0];
			let dmname = parts[dmid];
			contactDisplay(el, dmid, dmname[0]); //display name
			let els = document.getElementsByName(dmid);
			if(els.length>0){ //maybe different convo for same contact?
				if(!els[0].hasAttribute('id')){ //no, contact didn't have convo
					contacts.removeChild(els[0]);
					el.setAttribute('name', dmid); //this now becomes the new contact entry
				}
			}
		} else if(numparts > 1){ //group convo
			updateConvoText(el, window.convos[k]['participants']);
		}
	}
}
//Get conversations
async function refreshconvos(){
	let res = await fetch('/convos');
	let rjson = await res.json();
	console.log(JSON.stringify(rjson));
	window.convos = rjson['convos'];
	for(let k in window.convos){
		let parts = window.convos[k]['participants'];
		delete parts[window.jr['mykey']];
		ensureConvoDisplay(k, parts);
	}
}
window.names={};
function truster(b64pk, cname){
	return async () => {
		if(await confirmish('Are you sure you can trust this contact is '+cname+'?')){
			newContact(b64pk, cname, new Date().getTime() / 1000);
		}
	};
}
function contactDisplay(e, b64pk, cname){
	rmrf(e);
	if( ! window.displayNames[b64pk].verified){
		let unt = document.createElement('a');
		unt.href = '#';
		unt.addEventListener('click', truster(b64pk, cname));
		unt.appendChild(document.createTextNode('(UNVERIFIED) '));
		e.appendChild(unt);
	}
	e.appendChild(document.createTextNode(window.displayNames[b64pk].name+' '));
}
//Creates contact DOM
function addContact(b64pk, cname, trusted){
	if(trusted || !(b64pk in window.displayNames) || !window.displayNames[b64pk].verified){
		window.displayNames[b64pk] = {name: cname, verified: trusted};
	}
	if(b64pk === window.jr['mykey']){
		return; //don't add yourself
	}
	let els = document.getElementsByName(b64pk);
	let e = 0;
	if(els.length>0){
		e = els[0];
		rmrf(e);
	} else {
		console.log('ac', b64pk);
		e = document.createElement('p');
		e.className = 'contact';
		e.setAttribute('name', b64pk);
		let evtl = nameClick(b64pk);
		e.addEventListener('click', evtl);
		window.names[b64pk] = evtl;
		contacts.appendChild(e);
	}
	contactDisplay(e, b64pk, cname);
	let s = document.createElement('span');
	s.classList.add('contactkey');
	s.appendChild(document.createTextNode(b64pk));
	e.appendChild(s);
}
//converts byte array to b64 string
function tob64(pk){
	let bins='';
	for(let j = 0; j < pk.length; j++){
		bins+=String.fromCharCode(pk[j])
	}
	return btoa(bins).replace(/\//g,"_").replace(/\+/g,"-").replace(/=/g,""); //url_safe_no_pad
}
//accept an invite
async function acceptin(m){
	let res = await fetch('acceptinvite',{
		body: JSON.stringify({'cid': tob64(m['invitecid']), 'meetkey': tob64(m['meetkey']), 'seed': tob64(m['seed']), 'sesskey': tob64(m['sesskey']), 'meetaddr': m['meetaddr']}),
		headers: {'csrftoken': window.csrftok}
	});
	if(res.ok){
		let rjson = await res.json();
		console.log(rjson);
		addConvo(tob64(m['invitecid']), rjson['participants']);
	} else {
		alertish(await res.text());
	}
}

function getPath(n){
	if(!n){
		let s=document.getElementsByClassName('selectedf');
		n=(s.length == 0 ? sharedfolderlab : s[0]);
	}
	let pth = '';
	while(n != sharedfolder && n != sharedfolder.parentNode && n != sentfolder && n != sentfolder.parentNode){
		if('tagName' in n && n.tagName.toLowerCase() == 'li' && n.hasAttribute('name')){
			pth = n.getAttribute('name') + '/' + pth;
		}
		n = n.parentNode;
	}
	return pth;
}

function getCurFolderPath(){
	let s=document.getElementsByClassName('selectedf');
	let n=(s.length == 0 ? sharedfolderlab : s[0]);
	let pth = '';
	while(n != sharedfolder && n != sharedfolder.parentNode && n != sentfolder && n != sentfolder.parentNode){
		if('tagName' in n && n.tagName.toLowerCase() == 'li' && n.hasAttribute('name') && !n.classList.contains('file')){
			pth = n.getAttribute('name') + '/' + pth;
		}
		n = n.parentNode;
	}
	return pth;
}

function isSharedFile(n){
	while(n != sharedfolder.parentNode && n != sentfolder.parentNode){
		n = n.parentNode;
	}
	return n == sharedfolder.parentNode;
}

//uploads an array of files one after the other
function doUp(files, i, isShared, cid){
	if(i >= files.length){
		return;
	}
	let x = new XMLHttpRequest();
	let pth = (isShared?getCurFolderPath():'') + files[i].name;
	x.open('PUT', '/'+cid+'/'+pth);
	if(!isShared){
		x.setRequestHeader('x-lock','true');
	}
	x.addEventListener('load', () => {
		progressBar.value = 0;
		console.log("uploaded", pth, x);
		if(x.status >= 200 && x.status < 300){
			let hsh = x.getResponseHeader('X-Hash');
			let fid = parseInt(x.getResponseHeader('X-FID'), 10);
			pendMsg({'path':pth,'fid':fid,'timestamp':(new Date()).getTime(),'shared':isShared}, cid, hsh);
		}
		doUp(files, i + 1, isShared, cid);
	});
	x.upload.addEventListener('progress', (event) => progressBar.value = (event.loaded * 100 / event.total), false);
	progressBar.value = 0;
	x.send(files[i]);
}

//File upload
function fileup(fel,isShared){
	let chatting = document.getElementsByClassName('chatting');
	if(chatting.length === 0 || ! chatting[0].id){
		alertish('First start chatting with a contact');
		return;
	}
	doUp(fel.files, 0, isShared, chatting[0].id); //recurses for each
}
finp.addEventListener('change',() => {fileup(finp,false);});

chatwindow.addEventListener('dragover', (ev) => {
	ev.preventDefault();
});
chatwindow.sfdrags = 0;
chatwindow.addEventListener('dragenter', (ev) => {
	chatwindow.sfdrags++;
	chatwindow.style.backgroundColor = '#202020'
});
chatwindow.addEventListener('dragleave', (ev) => {
	chatwindow.sfdrags--;
	if(chatwindow.sfdrags === 0){
		chatwindow.style.backgroundColor = '#505050';
	}
});
chatwindow.addEventListener('drop', dropper(null, false));

attachbutton.addEventListener('click',() => {
	finp.click();
});

function getIdSelector(cid){
	return () => {
		console.log('clicking convo '+cid);
		clickContact(document.getElementById(cid));
	}
}
function ackMsg(ack,cid,seq){
	logchat(cid, window.pending[ack], true, window.jr['mykey'], seq);
	delete window.pending[ack];
	messages.removeChild(document.getElementById(cid+'.'+ack));
}
function accepter(f, m){
	return async () => {
		if(await confirmish('Invite received from '+displayName(f)+"\nto conversation "+tob64(m['invitecid']).substr(0,8)+"\n\nDo you wish to accept?")){
			acceptin(m);
		} else {
			console.log('Invite declined');
		}
	};
}

function vidPlayer(streamid){
	return () => {vidPlay(streamid)};
}
function vidPlay(streamid){
	console.log('vidPlay', streamid);
	let streamInfo = window.incomingvidstreams[streamid];
	let sourceBuffer = streamInfo.mediaSource.addSourceBuffer('video/webm; codecs="vp8"');
	sourceBuffer.addEventListener('updateend', (_) =>  {
		if(streamInfo.vidElement.readyState >= 3 && streamInfo.vidElement.paused){
			console.log('updateend starting real play '+streamInfo.vidElement.readyState);
			streamInfo.vidElement.play();
			console.log('do',streamInfo.mediaSource.readyState); // ended
		}else if(streamInfo.vidElement.paused){
			console.log('not starting real play? RS '+streamInfo.vidElement.readyState+' paused '+streamInfo.vidElement.paused);
		}
	});
	if(streamInfo.initchunk !== null){
		streamInfo.sourceBuffer = sourceBuffer;
		console.log('vid appending', streamInfo.initchunk);
		sourceBuffer.appendBuffer(streamInfo.initchunk);
	}
}
function newParseState(){
	return {offset: 0, inseg: false, postChunk: null, inclus: false, clusto: 0, inid: false, lasto: 0, tsadjust: 0, readingId: false};
}

//Submits a new video chunk to a stream. Handles loss detection/recovery as well
function submitVidChunk(streamInfo){
	let u8view = streamInfo.pendingBody;
	if(streamInfo.parseState.postChunk !== null){
		streamInfo.parseState.postChunk -= streamInfo.parseState.offset; //reset offsets
	}
	streamInfo.parseState.offset = 0;
	parseWebmChunk(streamInfo.parseState, u8view);
	if(streamInfo.parseState.inseg && !streamInfo.parseState.inclus){
		parseSeg(streamInfo.parseState, u8view);
	}
	//First we have mid-chunk loss mitigation attempts. These might fail with compression artifacts or freezes
	//but until we get a new keyframe, usually at a new WEBM chunk, we do the best we can
	if(streamInfo.pendingId > streamInfo.lastId + 1){ //lost at least 1 chunk
		streamInfo.lossDetected = true;
		streamInfo.parseState.readingId = false; //TODO: what if we're in the middle of an ID? spoof a new cluster I guess
		if(new Uint32Array(u8view.slice(0,4).buffer)[0] == new Uint32Array(new Uint8Array([0x1F, 0x43, 0xB6, 0x75]).buffer)[0]){
			console.log('LOST VIDEO SECTIONS '+(streamInfo.lastId+1)+'-'+(streamInfo.pendingId-1)+" GUESSING WE'RE STARTING A NEW CLUSTER. old inid "+streamInfo.parseState.inid);
			streamInfo.parseState.inid = false;
		}else if(u8view[0] == 0x43 && u8view[1] == 0xB6 && u8view[2] == 0x75){
			console.log('LOST VIDEO SECTIONS '+(streamInfo.lastId+1)+'-'+(streamInfo.pendingId-1)+' PARTIAL CLUSTER. old inid '+streamInfo.parseState.inid);
			streamInfo.parseState.inid = false;
			let temp = new Uint8Array(u8view.length + 1);
			temp[0] = 0x1F;
			temp.set(u8view, 1);
			u8view = temp;
		}else if(u8view[0] == 0x10 || u8view[0] == 0x11){
			console.log('LOST VIDEO SECTIONS '+(streamInfo.lastId+1)+'-'+(streamInfo.pendingId-1)+' Potential lost A3');
			if(streamInfo.parseState.inid !== 0xa3){
				console.log('Inserting new A3');
				streamInfo.parseState.inid = false;
				let temp = new Uint8Array(u8view.length + 1);
				temp[0] = 0xA3;
				temp.set(u8view, 1);
				u8view = temp;
			}
		}else{
			console.log('LOST VIDEO SECTIONS '+(streamInfo.lastId+1)+'-'+(streamInfo.pendingId-1)+' UNSURE WHERE WE ARE');
		}
	}
	//Now we handle the real loss recovery; this is what we do after a loss has been detected when we have a new cluster - we restart the stream
	let restarted = false;
	if(streamInfo.lossDetected && streamInfo.initchunk !== null){//restart on a new cluster after loss
		let lossrestart = null;
		if(new Uint32Array(u8view.slice(0,4).buffer)[0] == new Uint32Array(new Uint8Array([0x1F, 0x43, 0xB6, 0x75]).buffer)[0]){
			console.log('LOSS RESTART 4 NEW CLUSTER. INITCHUNK ',streamInfo.initchunk);
			lossrestart = 4;
		}else if(u8view[0] == 0x43 && u8view[1] == 0xB6 && u8view[2] == 0x75){
			console.log('LOSS RESTART 3 PARTIAL CLUSTER. INITCHUNK ',streamInfo.initchunk);
			lossrestart = 3;
		}
		if(lossrestart !== null){
			//STEP 1: create new WEBM data for a newly restarting stream using our saved initchunk and new cluster data we just got
			streamInfo.lossDetected = false;
			streamInfo.parseState = newParseState(); //restart parse state from scratch.
			parseWebmChunk(streamInfo.parseState, streamInfo.initchunk);//figure out how much of the initchunk is before the first cluster ID
			if(streamInfo.parseState.inseg){ //this should be true if we ever had a good stream
				let lastoff = parseSeg(streamInfo.parseState, streamInfo.initchunk); //Parse segment headers. Maybe we'll get a cluster opening or maybe not
				let initTaking = (streamInfo.parseState.inclus ? lastoff - 4//If we ate the cluster opening; go back 4 bytes from the end of cluster ID.
					: (streamInfo.parseState.postChunk ? streamInfo.parseState.postChunk : undefined)); //No cluster opening so just use the end of the last segment header
				let tmplen = initTaking + 4 + u8view.length - lossrestart; //headers not including cluster ID + 4 byte cluster ID + new cluster after ID
				let tmp = new Uint8Array(tmplen);
				tmp.set(streamInfo.initchunk.slice(0,initTaking), 0);          //headers not including cluster ID
				tmp.set(new Uint8Array([0x1F, 0x43, 0xB6, 0x75]), initTaking); //4 byte cluster ID
				tmp.set(u8view.slice(lossrestart), initTaking + 4);            //new cluster after ID
				streamInfo.initchunk = tmp; //submit all of it when our video's running
				u8view = tmp; //also use in this function
				parseSeg(streamInfo.parseState, u8view); //If we didn't parse the cluster opening yet, do so now.
				console.log('initchunk ',streamInfo.initchunk, JSON.stringify(streamInfo.parseState));
			}else{
				console.log('BAD WEBM?',streamInfo.initchunk, JSON.stringify(streamInfo.parseState));
				throw 'BAD WEBM?';
			}

			//STEP 2: restart the video element on the page with a new MediaSource+URL+buffer
			let mediaSource = new MediaSource;
			mediaSource.addEventListener('sourceopen', vidPlayer(streamInfo.streamId));
			let oldurl = streamInfo.vidElement.src;
			streamInfo.vidElement.src = URL.createObjectURL(mediaSource);
			URL.revokeObjectURL(oldurl);
			streamInfo.mediaSource = mediaSource;
			streamInfo.sourceBuffer = null;
			restarted = true;
		}
	}
	//Parse our current data chunk
	streamInfo.lastId = streamInfo.pendingId;
	while(streamInfo.parseState.inclus && streamInfo.parseState.offset < u8view.length){
		parseClus(streamInfo.parseState, u8view);
		if(streamInfo.parseState.offset < u8view.length && streamInfo.parseState.inid !== false){
			parseClusEl(streamInfo.parseState, u8view);
		}
	}
	if(restarted)
		return; //don't append to the source buffer yet; we forged everything
	if(streamInfo.sourceBuffer === null){ //MediaSource exists but is not ready yet
		if(streamInfo.initchunk === null){
			console.log('ERROR SUBMITTING NO INIT CHUNK?');
		}else{
			console.log('APPENDING TO INIT CHUNK');
			let tmp = new Uint8Array(streamInfo.initchunk.length + u8view.length);
			tmp.set(streamInfo.initchunk, 0);
			tmp.set(u8view, streamInfo.initchunk.length);
			streamInfo.initchunk = tmp;
		}
	} else {
		try{
			streamInfo.sourceBuffer.appendBuffer(u8view);
		}catch(e){
			console.log('Error appending. Loss? '+streamInfo.lossDetected+' ps '+JSON.stringify(streamInfo.parseState)+' err? '+streamInfo.vidElement.error);
		}
	}
}

//dispatches JSON inbound objects pushed from the server
function process(j){
	if(!('msg' in j)||!('from' in j))
		return;
	let f = j['from'];
	let m = j['msg'];
	console.log('Received', j);
	if('newcon' in m && 'convoid' in m){ //new connection notification
		if(!document.getElementById(m['convoid'])){
			refreshconvos();
		}
	} else if ('ack' in j['midpoint'] && 'convoid' in j && 'seq' in j){ //acked message
		if(j['midpoint']['ack'] in window.pending){
			ackMsg(j['midpoint']['ack'], j['convoid'], j['seq']);
		}else{
			window.pending[j['midpoint']['ack']] = j['seq'];
		}
	} else if ('op' in j['midpoint'] && 'convoid' in j && 'seq' in j){ //midpoint message
		if(j['midpoint']['op'] == 'del'){
			rmfnode(j['convoid']+'_f_'+j['midpoint']['fid']);
		} else if (j['midpoint']['op'] == 'ume' && 'path' in m){ //move fid to new path
			addFile({'id':j['midpoint']['newfid'],'met':{'path':m['path']},'lock':false,'deleted':false},j['convoid']);
			rmfnode(j['convoid']+'_f_'+j['midpoint']['fid']);
		} else if (j['midpoint']['op'] == 'lve' && 'lve' in m){ //someone left
			logchat(j['convoid'], m, false, f, j['seq']);
		} else if (j['midpoint']['op'] == 'ent' && 'ent' in m){ //someone entered
			logchat(j['convoid'], m, false, f, j['seq']);
		}
	} else if ('vid_request' in m){
		if(m['vid_request'] === window.videoSid){
			console.log('Good vid request. '+window.videoSid, window.firstvchunk.length);
			sendvChunks(new Blob([window.firstvchunk]), j['convoid'], window.videoSid, 0, [window.firstvchunk.length]);//resend first chunk
		}
	} else if ('vid_stop' in m){
		let streamId = m['vid_stop'];
		if(streamId in window.incomingvidstreams){
			let streamInfo = window.incomingvidstreams[streamId];
			if(streamInfo.sender === j['from']){
				stopVid(streamId);
			}
		}
	} else if ('convoid' in j){ //normal E2E message
		let s =  ('seq' in j ? j['seq'] : null);
		logchat(j['convoid'], j['msg'], f===window.jr['mykey'], f, s);
		if(s !== null && !(f in window.convos[j['convoid']]['participants']) && f !== window.jr['mykey']) {
			refreshconvos(); //new participant
		}
	}
	if('convoid' in j){
		let el=document.getElementById(j['convoid']);
		if(!el){//we don't know about this convo yet?
			console.log("didn't find convo ",JSON.stringify(j['convoid']),el);
			refreshconvos().then(getIdSelector(j['convoid']));
		}else{
			clickContact(el);
		}
	}
}

//Returns a function to stop a specific video stream
function vidStopper(streamId){
	return () => {stopVid(streamId);}
}

//Stops an incoming video stream.
function stopVid(streamId) {
	if(streamId in window.incomingvidstreams){
		console.log('Stopping video '+streamId);
		let streamInfo = window.incomingvidstreams[streamId];
		try{
			streamInfo.mediaSource.endOfStream();
		}catch(e){console.log(e);}
		try{
			streamInfo.vidElement.parentNode.remove();
		}catch(e){console.log(e);}
		delete window.incomingvidstreams[streamId];
		if(Object.keys(window.incomingvidstreams).length === 0 && !window.aud){
			stopCall();
		}
	}
}

//Removes a file/dir node
function rmfnode(nodid){
	if(!window.deletedfids){
		window.deletedfids = {};
	}
	window.deletedfids[nodid] = 1;
	let e = document.getElementById(nodid);
	if(e){
		let ch = document.getElementById(nodid+'_children');
		if( ! ch || ch.childNodes.length == 0){ //not a folder or no children
			e.remove();
		}else{console.log('rmfnode bailing',ch, (ch && ch.childNodes ? ch.childNodes.length : 0) + " " + ch.innerText);}
	}
}

acceptcall.addEventListener('click', (e) => {
	acceptcall.style.display = 'none';
	callindicator.style.backgroundColor = 'lightgreen';
	callindicatortext.innerHTML = '📞 In call';
	startCall(window.pendingcallcid, () => {});
});

stopcallbutton.addEventListener('click', stopCall);
window.pb = {};
window.hungups = {};

//show incoming call notification if we haven't accepted yet, hide if we've rejected, or execute the below if in call:
function showCall(cid, nextf){
	if(window.answertimeout){
		clearTimeout(window.answertimeout);
		window.answertimeout = null;
	}
	if(callindicator.style.display != 'inline'){//display ringing
		//but only if we haven't hung up on them in the past 10 seconds
		if(!(cid in window.hungups) || new Date().getTime() - window.hungups[cid] > 10000){
			console.log('showing callindicator');
			callindicator.style.display='inline';
			callindicator.style.backgroundColor = 'lightblue';
			acceptcall.style.display = 'inline';
			videoAcceptButton.style.display = 'inline';
			window.pendingcallcid = cid;
			window.answertimeout = setTimeout(stopCall, 20000);// if remote end drops, ignore
			rmrf(callindicatortext);
			if(window.incomingvideo){
				callindicatortext.appendChild(document.createTextNode('Incoming video call 📱 from '+window.incomingvideo['disp']));
			}else{
				callindicatortext.innerHTML = 'Incoming call 📱';
			}
		} else {
			console.log('hung up - ignoring call packets');
		}
	}else if(callindicator.style.backgroundColor !== 'lightblue'){ //if in call
		console.log('showCall nextf', cid == window.callcid, cid, window.callcid);
		if(window.callcid != cid) { //another incoming video call. Notify user?
		}else if(nextf){//video should already be started
			nextf();
		}
	}
}
function handleVidPacket(vidStreamId, packetNum, offset, total, convoid, sender, vidData){
	if(!window.incomingvideo){
		window.incomingvideo = {'cid':convoid,'disp':displayName(sender)};
	}
	if(vidStreamId in window.incomingvidstreams){
		clearTimeout(window.incomingvidstreams[vidStreamId].stopTimeout); // new packet, reset timeout
	} else {
		console.log('NEW INCOMING VIDEO STREAM');
		let mediaSource = new MediaSource;
		mediaSource.addEventListener('sourceopen', vidPlayer(vidStreamId));
		let vidp = document.createElement('video');
		vidp.src = URL.createObjectURL(mediaSource);
		vidp.classList.add('fitvid');
		vidp.addEventListener('click',()=>{vidp.requestFullscreen()});
		vidp.addEventListener('play', setVidSizes);
		let stopper = vidStopper(vidStreamId);
		window.incomingvidstreams[vidStreamId] = {stopper: stopper, stopTimeout: 0, streamId: vidStreamId, sourceBuffer: null, initchunk: null, mediaSource: mediaSource, vidElement: vidp, pendingBody: null, sender: sender, pendingId: null, lastId: null, pendingParts: {}, lossDetected: false, parseState: newParseState()};
		let viditem = document.createElement('div');
		viditem.appendChild(vidp);
		viditem.classList.add('item');
		vidcontainer.appendChild(viditem);
		setVidSizes();
		mediaSource.from_id = vidStreamId;
	}
	let streamInfo = window.incomingvidstreams[vidStreamId];
	streamInfo.stopTimeout = setTimeout(streamInfo.stopper, 10000); // set new timeout
	if(streamInfo.pendingId === null || packetNum > streamInfo.pendingId){
		if(streamInfo.pendingId === null && packetNum > 0){
			console.log('Requesting stream start chunk for', vidStreamId);
			fetch('/requestvid', {
				method: 'POST',
				body: vidStreamId,
				headers: {'csrftoken': window.csrftok, 'cid': convoid}
			});
		}else{
			streamInfo.pendingParts = {};
			streamInfo.pendingBody = new Uint8Array(total);
			streamInfo.pendingId = packetNum;
		}
	}
	if(streamInfo.pendingId !== null && packetNum === streamInfo.pendingId){
		streamInfo.pendingParts[offset] = vidData.length;
		streamInfo.pendingBody.set(vidData, offset);
		let complete = true;
		for(let i = 0; i < total; i+=streamInfo.pendingParts[i]){
			if(!(i in streamInfo.pendingParts)){
				complete = false;
				break;
			}
		}
		if(complete){
			if(packetNum === 0){ //first bit. Will be grabbed from source opening event
				try{
					console.log('PACKET 0 STREAM',streamInfo.pendingBody);
					parseWebmChunk(streamInfo.parseState, streamInfo.pendingBody); //parses outer container if present
					if(streamInfo.parseState.inseg && ! streamInfo.parseState.inclus){ //before cluster
						parseSeg(streamInfo.parseState, streamInfo.pendingBody);
						if(streamInfo.parseState.inclus){
							parseClus(streamInfo.parseState, streamInfo.pendingBody);
						}
						if(streamInfo.parseState.offset < streamInfo.pendingBody.length && streamInfo.parseState.inid === false){
							parseClusEl(streamInfo.parseState, streamInfo.pendingBody);
						}
						console.log('there we are off',streamInfo.parseState.offset,'inclus',streamInfo.parseState.inclus);
					}
					streamInfo.initchunk = streamInfo.pendingBody;
				}catch(e){
					console.log('WEBM PARSE FAIL',e);
				}
			}else{
				submitVidChunk(streamInfo);
			}
		}
	}else{
		console.log('out of order vid num '+packetNum+' off '+offset+' tot '+total+' for '+vidStreamId);
	}
	showCall(convoid, () => {});
}
//Run monitor. Async with fetch so we can loop and not have infinitely growing call stack of XHR response -> XHR request ->...
async function pollmonitor(){
	while(true){
		let response = await fetch('/nextmsg',{headers: {'csrftoken': window.csrftok}});
		if(response.ok){
			if(response.headers.get('content-type').toLowerCase() == 'application/octet-stream'){
				let sender = response.headers.get('X-From');
				let cid = response.headers.get('X-Convo-Id');
				let ts = parseInt(response.headers.get('X-Timestamp'), 10);
				if(Math.abs(new Date().getTime() - ts) > 5 * 60 * 1000){
					console.log('Bad audio timestamp ', Math.abs(ts - new Date().getTime()) / 1000, ' sec off');
				}else if(response.headers.get('X-Media') === '16bitaud'){
					response.arrayBuffer().then((respdata) => {
						showCall(cid, () => {
							if(!(sender in window.pb)){ //starting audio
								window.pb[sender] = new SnippetBuffer();
							}
							window.pb[sender].addSnippet(respdata); //queue up next audio chunk
							window.answertimeout = setTimeout(stopCall, 5000);// if remote end drops for 5 seconds, end call
						});
					});
				}else if(response.headers.get('X-Media') === 'vid'){
					let vidStreamId = response.headers.get('X-Stream');
					let packetNum = parseInt(response.headers.get('X-Packet'), 10);
					let offset = parseInt(response.headers.get('X-Offset'), 10);
					let total = parseInt(response.headers.get('X-Total'), 10);
					response.arrayBuffer().then((respdata) => {
						handleVidPacket(vidStreamId, packetNum, offset, total, cid, sender, new Uint8Array(respdata));
					});
				} else {
					console.log('bad bin response header?', response.headers.get('X-Media'));
				}
			} else {
				response.json().then(process);
			}
		}else{
			let txt = await response.text();
			if(txt !== 'timeout waiting for something to happen')
				console.log('Error response',txt);
			if(txt === 'Bad CSRF token')
				break;
		}
	}
	alertish('Broken connection to schadnfreude, possibly opened in new tab or exited. Recommend closing this tab.');
}
//Get contacts
async function getContacts(){
	let response = await fetch('/contacts');
	let contacts = await response.json();
	let rsp = contacts['contacts'];
	window.displayNames = {};
	for(let ctk in rsp){
		addContact(ctk, rsp[ctk]['name'], rsp[ctk]['verified']);
	}
}
//Scrollback
messages.addEventListener('scroll',() => {
	let chatting = document.getElementsByClassName('chatting');
	if(chatting.length > 0 && chatting[0].hasAttribute('id') && messages.scrollTop === 0){ //check for priors
		let cid=chatting[0].getAttribute('id');
		let earliest = null;
		window.savedchats[cid].seqs.forEach((seq) => {
			if(earliest === null || (typeof seq === 'number' && seq < earliest)){
				earliest = seq;
			}
		});
		if(earliest !== null && earliest > 0){ //Grab more earlier
			fetch('/msghistory?'+cid+'.'+earliest);
		}
	}
});

//Get new CSRF token to ensure only one UI up at once
async function csrfReq(){
	let response = await fetch('/csrftoken', {method: 'POST', headers: {'csrftoken': window.csrftok}});
	window.csrftok = await response.text();
}
myinfobutton.addEventListener('click', () => {
	loadMyInfo(window.jr['mykey'], window.jr['dname']);
});
addbutton.addEventListener('click', () => {
	container.style.display='none';
	contactmodal.style.display='flex';
});
exitbutton.addEventListener('click', async () => {
	if(await confirmish('Exit?')){
		fetch('/shutdown', {method: 'POST', headers: {'csrftoken': window.csrftok}}).then(()=>{
			window.close();
			setTimeout(()=>{alertish('schadnfreude has exited. Please close this window;');},1);//only fires if window doesn't close
		});
	}
});
infobtn.addEventListener('click', async () => {
	container.style.display='flex';
	myinfo.style.display='none';
	bootstrap();
	if(dname.value != dname.getAttribute('initialval') && dname.value.length > 0){
		if(await confirmish('Are you sure you want to change your name? Existing contacts will be prompted to verify your new name.')){
			setname(dname.value); //changing display name
		}
	}
});

function loadMyInfo(myid, mydispname){
	firstrun.style.display='none';
	container.style.display='none';
	myinfo.style.display='flex';
	mysfid.value = myid; //update ID code and display name
	dname.value = mydispname;
	dname.setAttribute('initialval', mydispname);
	rmrf(myidqr);
	if(!window.QRCode){
		let qrscript = document.createElement('script');
		qrscript.addEventListener('load', () => {
			new QRCode(myidqr,'sf:'+myid);
		});
		qrscript.src = '/qrcode.min.js';
		document.head.appendChild(qrscript);
	}else{
		new QRCode(myidqr,'sf:'+myid);
	}
}
async function setname(dspname){
	let response = await fetch('/name', {
		method: 'POST',
		body: dspname,
		headers: {'csrftoken': window.csrftok}
	});
	setupbtn.disabled = false;
	if(response.ok){
		if(window.jr){
			window.jr['dname'] = dspname; //when updating
			loadMyInfo(window.jr['mykey'], dspname);
		}else{
			loadMyInfo(window.setupId, dspname);
		}
	}else{
		let txt = await response.text();
		if(txt.indexOf('Update requires restart') !== -1) {
			if(await confirmish(txt)){
				//restart if we can
				let shutdown_resp = await fetch('/shutdown?restart', {
					method: 'POST',
					headers: {'csrftoken': window.csrftok}
				});
				if(!shutdown_resp.ok){
					let txt = await shutdown_resp.text();
					alertish(txt);
				}
				window.close();
			}
		}else{
			alertish('Error - ' + txt);
		}
	}
}
setupbtn.addEventListener('click', () => {
	setupbtn.disabled = true;
	setname(dispname.value);
});

//Get my info
async function bootstrap(){
	if(window.bootstrapped){
		return;
	}
	window.incomingvidstreams = {};
	let response = await fetch('/myinfo');
	if(!response.ok){
		let txt = await response.text();
		alertish(txt);
		return;
	}
	let jr = await response.json();
	console.log(jr);
	if('errnomeet' in jr){
		window.setupId = jr['errnomeet']; //temporarily save since we dont' have complete info yet
		window.csrftok = jr['csrt'];
		firstrun.style.display='flex';
		container.style.display='none';
		setupbtn.disabled=!jr['synced'];
		if(setupbtn.disabled){ //wait a sec and try again
			setTimeout(bootstrap, 500);
		} else {
			rmrf(setupbtn);
			setupbtn.appendChild(document.createTextNode('Complete setup'));
		}
	} else {
		firstrun.style.display='none';
		container.style.display='flex';
		myinfo.style.display='none';
		window.jr = jr;
		window.csrftok = jr['csrftoken'];
		csrfReq().then(getContacts).then(refreshconvos).then(pollmonitor);
		window.addEventListener('resize', setVidSizes);
		localVideo.addEventListener('play', setVidSizes);
		window.bootstrapped = true;
	}
}
bootstrap(); //kick it off

function selectf(lab){
	return () => {
		deselectf();
		lab.classList.add('selectedf');
	}
}
function deselectf(){
	[].forEach.call(document.getElementsByClassName('selectedf'),(e) => {
		e.classList.remove('selectedf');
	});
}
function ensureNode(nod,parts,idx,cid,fid,fold){
	console.log('ensureNode',nod,parts,idx,cid,fid,fold);
	if(window.deletedfids && (cid+'_f_'+fid) in window.deletedfids){
		console.log('notice of old deleted fid', fid);
		return;
	}
	if(idx >= parts.length){
		return nod;
	}
	let fn = parts[idx];
	let cn=nod.childNodes;
	for(let i =0; i < cn.length; i++){
		if('getAttribute' in cn[i] && cn[i].getAttribute('name') === fn){//we found it
			let nd=cn[i];
			if(nd.classList.contains('file')){
				return nd;
			}else if(nd.tagName.toLowerCase() === 'ol'){
				return ensureNode(nd,parts,idx+1,cid,fid,fold); //done
			}else{
				return ensureNode(nd,parts,idx,cid,fid,fold);
			}
		}
	}
	//Not found, make it
	let l = document.createElement('li');
	l.setAttribute('name', fn);
	if(idx === parts.length-1 && !fold){ //is it a file?
		let a = document.createElement('a');
		a.setAttribute('href', '/download?'+cid+'.'+fid);
		a.setAttribute('download', fn);
		a.appendChild(document.createTextNode(fn));
		let fs = selectf(a);
		a.addEventListener('click', (e) => {
			e.preventDefault();
			fs();
		});
		a.addEventListener('dragstart', (e) => {window.draggedf=e.target.parentNode});
		l.setAttribute('id', cid+'_f_'+fid);
		l.appendChild(a);
		l.className='file';
		nod.appendChild(l);
		return l;
	}
	let inp = document.createElement('input');
	inp.setAttribute('type', 'checkbox');
	let ol = document.createElement('ol');
	ol.setAttribute('name', fn);
	//otherwise a dir  (<li><label for="folder1">Shared files</label> <input type="checkbox" checked id="folder1" /><ol id="sharedfolder">)
	let lab = document.createElement('label');
	lab.appendChild(document.createTextNode(fn));
	let selector = selectf(lab);
	lab.addEventListener('click', selector);
	lab.addEventListener('dragenter', selector);
	lab.addEventListener('dragleave', deselectf);
	lab.addEventListener('dragover', (ev) => {
		if(window.draggedf && getPath(window.draggedf.parentNode) != getPath(lab)) // different folder
			ev.preventDefault();
		else if(ev.dataTransfer && ev.dataTransfer.items && ev.dataTransfer.items.length > 0 && ev.dataTransfer.items[0].kind === 'file')
			ev.preventDefault();
	});
	lab.addEventListener('drop', dropper(selector, true));
	l.appendChild(lab);
	l.appendChild(document.createTextNode(' '));
	l.appendChild(inp);
	l.appendChild(ol);
	l.setAttribute('folder','true');
	if(idx == parts.length-1){
		l.setAttribute('id', cid+'_f_'+fid);
		ol.setAttribute('id', cid+'_f_'+fid+'_children');
	}
	nod.appendChild(l);
	return ensureNode(ol,parts,idx+1,cid,fid,fold);
}
//Adds a shared or sent file to the display
function addFile(f,cid){//f = {"id":0,"met":{"path":"heart.jpg"},"len":79885,"lock":true,"deleted":false}
	if(!f['met']['path']){
		return;
	}
	let parts = f['met']['path'].split('/');
	let par = sharedfolder;
	if(f['lock']){
		par=sentfolder;
	}
	ensureNode(par,parts,0,cid,f['id'],'type' in f['met'] && f['met']['type'] == 'fold');
}

//toggles whether shared folder view is visible
function toggleshared(){
	let s = shared;
	let d = dragbar2;
	if(s.style.display == 'flex'){
		s.style.display = 'none';
		d.classList.add('hiddn');
		chatwindow.classList.remove('hidmobl');
		chatwindow.style.display='flex';
		s.classList.add('hidmobl');
		rmrf(sentfolder);
		rmrf(sharedfolder);
		return;
	}else{
		showshare.style.fontSize = '';
		showshare.style.fontWeight = '';
		s.style.display = 'flex';
		d.classList.remove('hiddn');
		s.classList.remove('hidmobl');
		chatwindow.style.display='';
		chatwindow.classList.add('hidmobl');
		d.classList.add('blockdesk');
	}
	showshared();
}
function showshared(){
	let chatting = document.getElementsByClassName('chatting');
	if(chatting.length > 0 && chatting[0].hasAttribute('id')){ //check for priors
		let cid=chatting[0].getAttribute('id');
		let x = new XMLHttpRequest();
		x.open('GET', '/listfiles?'+cid);
		x.seenBytes = 0;
		x.onreadystatechange = () =>  { 
			if(x.readyState > 2) {
				console.log('update', x.readyState);
				let next=x.responseText.indexOf("\n",x.seenBytes);
				while(next != -1){
					let f=JSON.parse(x.responseText.substr(x.seenBytes, next - x.seenBytes));
					if(!f['deleted']){
						addFile(f, cid);
					} else {
						rmfnode(document.getElementById(cid+'_f_'+f['id'])); //remove it if it's there
					}
					x.seenBytes = next + 1;
					next=x.responseText.indexOf("\n",x.seenBytes);
				}
			}
		};
		x.send();
	}
}
newdirbutton.addEventListener('click', () => {
	let flds=document.getElementsByClassName('selectedf');
	let chatting = document.getElementsByClassName('chatting');
	let f = (flds.length !== 1 ? sharedfolder : flds[0]);//default to root
	if(chatting.length == 0 || ! chatting[0].hasAttribute('id')){ //check for priors
		alertish('Select a conversation');
		return;
	}
	let cid=chatting[0].getAttribute('id');
	let fname=prompt('Enter new folder name');
	if(!fname || fname.indexOf("\\") != -1 || fname.indexOf('/') != -1){
		alertish('Folder name must not include slashes');
		return;
	}
	let fpath = getPath(null) + fname;
	//Do MKCOL request
	fetch('/'+cid+'/'+fpath, {method: 'MKCOL'}).then((response) => {
		if(response.ok){
			let fid = parseInt(response.headers.get('X-FID'), 10);
			ensureNode(f.parentNode,[f.parentNode.getAttribute('name'),fname],0,cid,fid,true);
		}
	});
});
function movef(draggedf, tgt){
	movefn(draggedf, getPath(tgt), draggedf.getAttribute('name'));
}
function movefn(draggedf, pathbase, fn){
	let path = pathbase + fn;
	let splits = draggedf.getAttribute('id').split('_f_');
	let cid = splits[0];
	let fid = parseInt(splits[1], 10);
	let srcpath = getPath(draggedf.parentNode) + draggedf.getAttribute('name');
	let dest = document.baseURI.substr(0, document.baseURI.lastIndexOf('/') + 1) + cid + '/' + path;
	fetch('/' + cid + '/' + srcpath, {method: 'MOVE', headers: {'destination': dest}}).then((r) => {
		console.log(r);
		if(r.ok){
			console.log('moved',srcpath,'to',path);
			let newfid = parseInt(r.headers.get('X-FID'), 10);
			addFile({'id':newfid,'met':{'path':path},'lock':false,'deleted':false},cid);
			draggedf.remove();
		}
	});
}
sharedfolderlab.addEventListener('click', selectf(sharedfolderlab));
sharedfolderlab.addEventListener('dragover', (ev) => {
	if(window.draggedf && getPath(window.draggedf.parentNode) != getPath(sharedfolderlab)){ // different folder
		ev.preventDefault();
	}else if(ev.dataTransfer && ev.dataTransfer.items && ev.dataTransfer.items.length > 0 && ev.dataTransfer.items[0].kind === 'file'){
		sharedfolderlab.style.fontWeight = 'bold';
		ev.preventDefault();
	}
});
function dropper(selector, shared){
	return (ev) => {
		ev.preventDefault();
		sharedfolderlab.style.fontWeight = '';
		chatwindow.style.backgroundColor = '#505050';
		if(window.draggedf){
			movef(window.draggedf, ev.target);
			window.draggedf = null;
		}else if (ev.dataTransfer.items) {
			let chatting = document.getElementsByClassName('chatting');
			if(chatting.length === 0 || ! chatting[0].id){
				alertish('First start chatting with a contact');
				return;
			}
			if(selector) selector();
			let files = [];
			for (let i = 0; i < ev.dataTransfer.items.length; i++) {
				if (ev.dataTransfer.items[i].kind === 'file') {
					files.push(ev.dataTransfer.items[i].getAsFile());
				}
			}
			doUp(files, 0, shared, chatting[0].id); //recurses for each
		}
	};
}
sharedfolderlab.addEventListener('dragleave', (ev) => sharedfolderlab.style.fontWeight = '');
sharedfolderlab.addEventListener('drop', dropper(null, true));
renamebutton.addEventListener('click', () => {
	let s = document.getElementsByClassName('selectedf');
	if(s.length != 1 || !('tagName' in s[0]) || s[0].tagName.toLowerCase() != 'a'){
		alertish('Select a file to rename');
		return;
	}
	let n = s[0].parentNode;
	let newname = prompt('Enter a new name');
	console.log(newname);
	if(newname && newname.indexOf('/') == -1 && newname.indexOf("\\") == -1){
		movefn(n, getPath(n.parentNode), newname)
	}
});
showshare.addEventListener('click', () => {toggleshared();});
fup.addEventListener('change',() => {fileup(fup, true);});
sharebutton.addEventListener('click',() => {
	fup.click();
});
downbutton.addEventListener('click',() => {
	let downl = document.getElementsByClassName('selectedf');
	for(let i = 0; i < downl.length; i++){
		let n = downl[i];
		if('tagName' in n && n.tagName.toLowerCase() == 'a'){
			let a = document.createElement('a');
			a.setAttribute('href', n.getAttribute('href'));
			a.setAttribute('download', n.getAttribute('download'));
			document.body.appendChild(a);
			a.click();
			a.remove();
		}
	}
});
async function deleteFileByNodeRecursive(n){
	let ols = Array.from(n.childNodes).filter((cn) => 'tagName' in cn && cn.tagName.toLowerCase() == 'ol');
	for(let i = 0; i < ols.length; i++){
		let childrn = ols[i].childNodes;
		for(let j = childrn.length - 1; j >= 0; j--){
			await deleteFileByNodeRecursive(childrn[j]);
		}
	}
	let nodid = n.getAttribute('id');
	if(nodid){
		let pth = getPath(n);
		if(pth.endsWith('/')){
			pth = pth.substr(0, pth.length-1);
		}
		console.log("DELETING ",nodid,"at",pth);
		let durl = '/'+nodid.split('_f_')[0]+"/"+pth;
		let r = await fetch(durl, {method: 'DELETE'});
		console.log(pth,"DELETE RES", r.ok);
		if(r.ok){
			rmfnode(nodid);
		} else {
			alertish('Delete of '+pth+' failed.');
		}
	}else{
		n.remove();
	}
}
delbutton.addEventListener('click', async () => {
	if(! await confirmish("Permanently delete?")){
		return;
	}
	let selected = document.getElementsByClassName('selectedf');
	for(let i = 0; i < selected.length; i++){
		let n = selected[i];
		if(isSharedFile(n)){
			deleteFileByNodeRecursive(n.parentNode);
		}
	}
});
messageinp.addEventListener('keydown',(e)=>{
	if (e.keyCode === 13 && !e.shiftKey) {
		sendMsg();
		e.preventDefault();
		return false;
	}
	return true;
}, true);
//moves the drag bar separating the shared folder
function drag(e) {
	document.selection ? document.selection.empty() : window.getSelection().removeAllRanges();
	let relx = e.pageX - container.offsetLeft - dragbar2.offsetWidth / 2;
	shared.style.flexGrow = (container.offsetWidth - dragbar2.offsetWidth - relx) / (relx / 3.0);
}
dragbar2.addEventListener('mousedown', () =>  {
	document.addEventListener('mousemove', drag);
});
dragbar2.addEventListener('mouseup', () =>  {
	document.removeEventListener('mousemove', drag);
});

leavebutton.addEventListener('click', async () => {
	let chatting = document.getElementsByClassName('chatting');
	if(chatting.length > 0 && chatting[0].hasAttribute('id')){
		let cid=chatting[0].getAttribute('id');
		if(await confirmish("Are you sure you want to leave this conversation?")){
			await fetch('/'+cid, {method: 'LEAVE'});
			clearChatUi();
			delete window.savedchats[cid];
			delete window.convos[cid];
		}
	}
});

//Mobile nav
backtoconvolist.addEventListener('click', () => {
	contacts.classList.remove('blockdesk');
	chatwindow.style.display='';
	chatwindow.classList.add('hidmobl');
	if(shared.style.display == 'flex') toggleshared();
});
backtoconvo.addEventListener('click', toggleshared);

gitbutton.addEventListener('click', () => {
	let chatting = document.getElementsByClassName('chatting');
	if(chatting.length === 0){
		return;
	}
	let cid = chatting[0].id;
	let host = document.location.origin.split('//')[1];
	if(navigator.platform.toLowerCase().indexOf("win") != -1){
		host = host.replace(/:/,"@");
		fetch('/'+cid+'/', {method: 'UNCPRIME'});
		alertish("To create and use a git repository in this conversation use the following commands from cmd.exe\n\n"
			+"git init --bare \\\\"+host+'\\'+cid+"\\somefolder\\\n"
			+"git clone \\\\"+host+'\\'+cid+"\\somefolder\\\n\n"
			+"Or if you are using the MINGW git bash:\n\n"
			+"git init --bare //"+host+'/'+cid+"/somefolder/\n"
			+"git clone //"+host+'/'+cid+"/somefolder/\n\n"
			+"Then you can use git clone <ThePathAbove> etc. in your own folders.");
	} else {
		alertish("To create, clone, and update a git repository in this conversation, mount the WebDAV share http://"+host+"/"+cid+"/ in "
		+"a local folder, say 'somefolder/' then run\n\n"
		+"git init --bare somefolder/reponame\n"
		+"git clone somefolder/reponame your/local/folder/");
	}
});
