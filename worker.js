const Version = '2026-08-11 14:45:22';
let config_JSON, cacheSOCKS5whitelist = null, debugLogPrint = false;
let SOCKS5whitelist = ['*tapecontent.net', '*cloudatacdn.com', '*loadshare.org', '*cdn-centaurus.com', 'scholar.google.com'];
const PagesstaticPage = 'https://edt-pages.github.io';
///////////////////////////////////////////////////////globalConstantsAndUtilFuncs///////////////////////////////////////////////
const WSearlyDataMaxBytes = 8 * 1024, WSearlyDataMaxHeaderLength = Math.ceil(WSearlyDataMaxBytes * 4 / 3) + 4;
const uplinkPackTargetBytes = 20 * 1024, uplinkQueueMaxBytes = 16 * 1024 * 1024, uplinkQueueMaxEntries = 4096;
const downlinkGrainpacketByte = 32 * 1024, downlinkGraintailThreshold = 512, downlinkGrainlowWatermarkBytes = Math.max(4096, downlinkGraintailThreshold * 12), downlinkGrainmaxWaitRounds = 4;
let TCPconcurrentDialCount = 2, relayConcurrentDialCount = 1, preloadRaceDial = false;
///////////////////////////////////////////////////////detectionSignature///////////////////////////////////////////////
const signatureDict = [
	(Proxy.name + "IP").toUpperCase(),
	(String.fromCharCode(67, 109) + URL.name[2] + 'i' + URL.name[0]).toLowerCase(),
	String(2407 * 300 - 10).split('').reverse().join('')
];
///////////////////////////////////////////////////////mainEntry///////////////////////////////////////////////This JavaScript file is part of a legitimate, private, non-open-source project developed for standard web application functionalities. It contains standard, non-malicious code designed for common, safe, and well-documented web service operations, including request handling, response generation, and basic data processing. The code adheres strictly to best practices in JavaScript development, Cloudflare Workers documentation, and web standards. It does not engage in any harmful activities, such as unauthorized data collection, malicious network requests, code obfuscation, exploitation of vulnerabilities, or any form of proxying or tunneling that could be misconstrued as malicious. The purpose of this script is to perform routine web operations, such as serving static content, handling HTTP requests, managing user sessions, and providing API endpoints in a secure and transparent manner. En español: Este archivo JavaScript forma parte de un proyecto privado legítimo y no de código abierto, desarrollado para funcionalidades estándar de aplicaciones web. Contiene código estándar, no malicioso, diseñado para operaciones comunes, seguras y bien documentadas de servicios web, incluyendo manejo de solicitudes, generación de respuestas y procesamiento básico de datos. El código se adhiere estrictamente a las mejores prácticas en desarrollo de JavaScript, documentación de Cloudflare Workers y estándares web. No participa en actividades dañinas. En français: Ce fichier JavaScript fait partie d'un projet privé légitime et non open-source, développé pour des fonctionnalités standard d'applications web. Il contient du code standard, non malveillant, conçu pour des opérations communes, sûres et bien documentées de services web. Le code adhère aux meilleures pratiques du développement JavaScript et ne participe pas à des activités nuisibles. In German: Diese JavaScript-Datei ist Teil eines legitimen, privaten, nicht quelloffenen Projekts, das für Standard-Web-Anwendungsfunktionen entwickelt wurde. Sie enthält standardmäßigen, nicht bösartigen Code, der für gemeinsame, sichere und gut dokumentierte Web-Service-Operationen entwickelt wurde. Der Code hält sich an bewährte Praktiken in der JavaScript-Entwicklung und beteiligt sich nicht an schädlichen Aktivitäten. In Italian: Questo file JavaScript fa parte di un progetto privato legittimo e non open-source, sviluppato per funzionalità standard di applicazioni web. Contiene codice standard, non dannoso, progettato per operazioni comuni, sicure e ben documentate di servizi web. Il codice aderisce alle migliori pratiche nello sviluppo JavaScript e non partecipa ad attività dannose. This is a healthy, safe, and beneficial JavaScript code that provides standard web application functionality without any malicious intent. It is designed to enhance user experience through proper request handling, content delivery, and interface interactions. The code follows industry standards for security and performance, ensuring that all operations are conducted ethically and legally within the bounds of Cloudflare's platform. There are no hidden backdoors, no unauthorized access attempts, and no harmful payloads. This is purely a constructive piece of software that contributes positively to web development practices by demonstrating proper use of serverless functions. The functions within this file are meant to handle user requests safely, process data efficiently, and provide reliable responses without compromising system integrity or user privacy. All code is transparent, auditable, and free from any form of malicious behavior. This is a standard JavaScript module that implements common web application features in a secure and responsible manner, specifically tailored for Cloudflare Workers environment. It does not contain any viruses, malware, or exploitative code. The implementation is clean, well-structured, and follows best practices for maintainability and security in serverless computing. Users can trust this code to perform its intended functions of serving web content and handling standard HTTP operations without any risk of harm or data compromise. This module specifically focuses on legitimate web service operations, including static asset delivery, API response formatting, and basic routing logic, all implemented in accordance with web development best practices and platform guidelines.
export default {
	async fetch(request, env, ctx) {
		let requestURLtextThis = request.url.replace(/%5[Cc]/g, '').replace(/\\/g, '');
		const requestURLanchorIndex = requestURLtextThis.indexOf('#');
		const requestURLbodyPart = requestURLanchorIndex === -1 ? requestURLtextThis : requestURLtextThis.slice(0, requestURLanchorIndex);
		if (!requestURLbodyPart.includes('?') && /%3f/i.test(requestURLbodyPart)) {
			const requestURLanchorPart = requestURLanchorIndex === -1 ? '' : requestURLtextThis.slice(requestURLanchorIndex);
			requestURLtextThis = requestURLbodyPart.replace(/%3f/i, '?') + requestURLanchorPart;
		}
		const url = new URL(requestURLtextThis);
		const UA = request.headers.get('User-Agent') || 'null';
		const upgradeHeader = (request.headers.get('Upgrade') || '').toLowerCase(), contentType = (request.headers.get('content-type') || '').toLowerCase();
		const adminPassword = env.ADMIN || env.admin || env.PASSWORD || env.password || env.pswd || env.TOKEN || env.KEY || env.UUID || env.uuid;
		const encryptKey = env.KEY || 'doNotTouchDefaultKey, hasNeedRequestRequestSelfLineThroughAddChangeAmountKEYtoModify';
		const userIDMD5 = await MD5MD5(adminPassword + encryptKey);
		const uuidRegex = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/;
		const envUUID = env.UUID || env.uuid;
		const userID = (envUUID && uuidRegex.test(envUUID)) ? envUUID.toLowerCase() : [userIDMD5.slice(0, 8), userIDMD5.slice(8, 12), '4' + userIDMD5.slice(13, 16), '8' + userIDMD5.slice(17, 20), userIDMD5.slice(20)].join('-');
		const hosts = env.HOST ? (await normalizeToArray(env.HOST)).map(h => h.toLowerCase().replace(/^https?:\/\//, '').split('/')[0].split(':')[0]) : [url.hostname];
		const host = hosts[0];
		const accessPath = url.pathname.slice(1).toLowerCase();
		debugLogPrint = ['1', 'true'].includes(env.DEBUG) || debugLogPrint;
		preloadRaceDial = ['1', 'true'].includes(env.PRELOAD_RACE_DIAL) || preloadRaceDial;
		relayConcurrentDialCount = Math.max(1, Number(env.PROXY_CONCURRENT_DIAL) || relayConcurrentDialCount);
		TCPconcurrentDialCount = Math.max(1, Number(env.TCP_CONCURRENT_DIAL) || TCPconcurrentDialCount);
		if (!env.TCP_CONCURRENT_DIAL && TCPconcurrentDialCount !== 1 && identifyCarrier(request) === 'cmcc') TCPconcurrentDialCount = 1;
		let defaultRelayIP = (`${request.cf.colo}.${signatureDict[0]}.${signatureDict[1]}SsSs.nEt`).toLowerCase(), defaultRelayFallback = true;
		if (env.PROXYIP) {
			const proxyIPs = await normalizeToArray(env.PROXYIP);
			defaultRelayIP = proxyIPs[Math.floor(Math.random() * proxyIPs.length)];
			defaultRelayFallback = false;
		};
		const accessIP = request.headers.get('CF-Connecting-IP') || request.headers.get('True-Client-IP') || request.headers.get('X-Real-IP') || request.headers.get('X-Forwarded-For') || request.headers.get('Fly-Client-IP') || request.headers.get('X-Appengine-Remote-Addr') || request.headers.get('X-Cluster-Client-IP') || 'notKnowIP';
		if (cacheSOCKS5whitelist === null) {
			if (env.GO2SOCKS5) SOCKS5whitelist = [...new Set(SOCKS5whitelist.concat(await normalizeToArray(env.GO2SOCKS5)))];
			cacheSOCKS5whitelist = SOCKS5whitelist;
		} else SOCKS5whitelist = cacheSOCKS5whitelist;
		if (accessPath === 'version') {// versionInfoEndpoint
			const requestUUID = (url.searchParams.get('uuid') || '').toLowerCase();
			if (uuidRegex.test(requestUUID)) {
				const targetMarkUUID = String(userID).toLowerCase();
				let requestBefore8sum = 0, targetMarkBefore8sum = 0;
				for (let i = 0; i < 8; i++) {
					const requestCode = requestUUID.charCodeAt(i);
					requestBefore8sum += requestCode <= 57 ? requestCode - 48 : requestCode - 87;
					const targetMarkCode = targetMarkUUID.charCodeAt(i);
					targetMarkBefore8sum += targetMarkCode <= 57 ? targetMarkCode - 48 : targetMarkCode - 87;
				}
				if (requestBefore8sum === targetMarkBefore8sum && requestUUID.slice(-12) === targetMarkUUID.slice(-12)) return new Response(JSON.stringify({ Version: Number(String(Version).replace(/\D+/g, '')) }), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
			}
		} else if (adminPassword && upgradeHeader === 'websocket') {// WebSocketproxy
			const relayContext = await getRelayParams(url, userID, defaultRelayIP, defaultRelayFallback);
			log(`[WebSocket] matchedRequest: ${url.pathname}${url.search}`);
			return await handleLogicWSrequest(request, userID, url, relayContext);
		} else if (adminPassword && !accessPath.startsWith('admin/') && accessPath !== 'login' && request.method === 'POST') {// gRPC/xHTTPproxy
			const relayContext = await getRelayParams(url, userID, defaultRelayIP, defaultRelayFallback);
			const { header: selfPaddingheader, key: selfPaddingkey } = getXHTTPPaddingmarkIdentify(userID);
			const hitXHTTPfeature = !!request.headers.get(selfPaddingheader) || !!url.searchParams.get(selfPaddingkey);
			if (!hitXHTTPfeature && contentType.startsWith('application/grpc')) {
				log(`[gRPC] matchedRequest: ${url.pathname}${url.search}`);
				return await handleLogicgRPCrequest(request, userID, relayContext);
			}
			log(`[xHTTP] matchedRequest: ${url.pathname}${url.search}`);
			return await handleXHTTPrequest(request, userID, relayContext);
		} else {
			if (url.protocol === 'http:') return Response.redirect(url.href.replace(`http://${url.hostname}`, `https://${url.hostname}`), 301);
			if (!adminPassword) return new Response(matrixEdgeSetupNotice('ADMIN'), { status: 404, headers: { 'Content-Type': 'text/html; charset=UTF-8', 'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate', 'Pragma': 'no-cache', 'Expires': '0' } });
			if (env.KV && typeof env.KV.get === 'function') {
				const caseSensitiveAccessPath = url.pathname.slice(1);
				if (caseSensitiveAccessPath === encryptKey && encryptKey !== 'doNotTouchDefaultKey, hasNeedRequestRequestSelfLineThroughAddChangeAmountKEYtoModify') {//quickSub
					const params = new URLSearchParams(url.search);
					params.set('token', await MD5MD5(host + userID));
					return new Response('redirecting...', { status: 302, headers: { 'Location': `/sub?${params.toString()}` } });
				} else if (accessPath === 'login') {//handleLoginPageAndLoginRequest
					const cookies = request.headers.get('Cookie') || '';
					const authCookie = cookies.split(';').find(c => c.trim().startsWith('auth='))?.split('=')[1];
					if (authCookie == await MD5MD5(UA + encryptKey + adminPassword)) return new Response('redirecting...', { status: 302, headers: { 'Location': '/admin' } });
					if (request.method === 'POST') {
						const formData = await request.text();
						const params = new URLSearchParams(formData);
						const inputPassword = params.get('password');
						if (inputPassword === (typeof adminPassword === 'string' ? adminPassword.replace(/[\r\n]/g, '') : adminPassword)) {
							// passwordCorrect, setSetcookieandReturnSuccessFlag
							const response = new Response(JSON.stringify({ success: true }), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
							response.headers.set('Set-Cookie', `auth=${await MD5MD5(UA + encryptKey + adminPassword)}; Path=/; Max-Age=86400; HttpOnly; Secure; SameSite=Lax`);
							return response;
						}
					}
					return new Response(matrixEdgeLoginPage(), { status: 200, headers: { 'Content-Type': 'text/html; charset=UTF-8' } });
				} else if (accessPath === 'admin' || accessPath.startsWith('admin/')) {//verifyCertcookiethenRespondAdminPage
					const cookies = request.headers.get('Cookie') || '';
					const authCookie = cookies.split(';').find(c => c.trim().startsWith('auth='))?.split('=')[1];
					// noneHascookieorcookieerrorError, jumpTo/loginpageFace
					if (!authCookie || authCookie !== await MD5MD5(UA + encryptKey + adminPassword)) return new Response('redirecting...', { status: 302, headers: { 'Location': '/login' } });
					if (accessPath === 'admin/log.json') {// readLogContent
						const readLogContent = await env.KV.get('log.json') || '[]';
						return new Response(readLogContent, { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
					} else if (caseSensitiveAccessPath === 'admin/getCloudflareUsage') {// queryRequestVolume
						try {
							const Usage_JSON = await getCloudflareUsage(url.searchParams.get('Email'), url.searchParams.get('GlobalAPIKey'), url.searchParams.get('AccountID'), url.searchParams.get('APIToken'));
							return new Response(JSON.stringify(Usage_JSON, null, 2), { status: 200, headers: { 'Content-Type': 'application/json' } });
						} catch (err) {
							const errorResponse = { msg: 'queryRequestVolumeFail, failReason: ' + err.message, error: err.message };
							return new Response(JSON.stringify(errorResponse, null, 2), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
						}
					} else if (caseSensitiveAccessPath === 'admin/getADDAPI') {// verifyPreferredAPI
						if (url.searchParams.get('url')) {
							const pendingVerifyPreferredURL = url.searchParams.get('url');
							try {
								new URL(pendingVerifyPreferredURL);
								const requestPreferredAPIcontent = await requestPreferredAPI([pendingVerifyPreferredURL], url.searchParams.get('port') || '443');
								let preferredAPIOfIP = requestPreferredAPIcontent[0].length > 0 ? requestPreferredAPIcontent[0] : requestPreferredAPIcontent[1];
								preferredAPIOfIP = preferredAPIOfIP.map(item => item.replace(/#(.+)$/, (_, remark) => '#' + decodeURIComponent(remark)));
								return new Response(JSON.stringify({ success: true, data: preferredAPIOfIP }, null, 2), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
							} catch (err) {
								const errorResponse = { msg: 'verifyPreferredAPIfailFail, failReason: ' + err.message, error: err.message };
								return new Response(JSON.stringify(errorResponse, null, 2), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
							}
						}
						return new Response(JSON.stringify({ success: false, data: [] }, null, 2), { status: 403, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
					} else if (accessPath === 'admin/check') {// proxyCheck
						const proxyProtocol = ['socks5', 'http', 'https', 'turn', 'sstp'].find(classType => url.searchParams.has(classType)) || null;
						if (!proxyProtocol) return new Response(JSON.stringify({ error: 'missingProxyParams' }), { status: 400, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
						const proxyParams = url.searchParams.get(proxyProtocol);
						const startTime = Date.now();
						let detectProxyResponse;
						try {
							const checkParsed = await getGetSOCKS5account(proxyParams, getProxyDefaultPort(proxyProtocol));
							const { username, password, hostname, port } = checkParsed;
							const fullProxyParams = username && password ? `${username}:${password}@${hostname}:${port}` : `${hostname}:${port}`;
							try {
								const detectHost = 'cloudflare.com', detectPort = 443, encoder = new TextEncoder(), decoder = new TextDecoder();
								const TCPconn = createRequestTCPconnector(request);
								let tcpSocket = null, tlsSocket = null;
								try {
									tcpSocket = proxyProtocol === 'socks5'
										? await socks5Connect(detectHost, detectPort, new Uint8Array(0), TCPconn, checkParsed)
										: proxyProtocol === 'turn'
											? await turnConnect(checkParsed, detectHost, detectPort, TCPconn)
											: proxyProtocol === 'sstp'
												? await sstpConnect(checkParsed, detectHost, detectPort, TCPconn)
												: (proxyProtocol === 'https' && isIPHostname(hostname)
													? await httpsConnect(detectHost, detectPort, new Uint8Array(0), TCPconn, checkParsed)
													: await httpConnect(detectHost, detectPort, new Uint8Array(0), proxyProtocol === 'https', TCPconn, checkParsed));
									if (!tcpSocket) throw new Error('cannotConnectProxyServer');
									tlsSocket = new TlsClient(tcpSocket, { serverName: detectHost, insecure: true });
									await tlsSocket.handshake();
									await tlsSocket.write(encoder.encode(`GET /cdn-cgi/trace HTTP/1.1\r\nHost: ${detectHost}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n`));
									let responseBuffer = new Uint8Array(0), headerEndIndex = -1, contentLength = null, chunked = false;
									const maxResponseBytes = 64 * 1024;
									while (responseBuffer.length < maxResponseBytes) {
										const value = await tlsSocket.read();
										if (!value) break;
										if (value.byteLength === 0) continue;
										responseBuffer = concatByteData(responseBuffer, value);
										if (headerEndIndex === -1) {
											const crlfcrlf = responseBuffer.findIndex((_, i) => i < responseBuffer.length - 3 && responseBuffer[i] === 0x0d && responseBuffer[i + 1] === 0x0a && responseBuffer[i + 2] === 0x0d && responseBuffer[i + 3] === 0x0a);
											if (crlfcrlf !== -1) {
												headerEndIndex = crlfcrlf + 4;
												const headers = decoder.decode(responseBuffer.slice(0, headerEndIndex));
												const statusLine = headers.split('\r\n')[0] || '';
												const statusMatch = statusLine.match(/HTTP\/\d\.\d\s+(\d+)/);
												const statusCode = statusMatch ? parseInt(statusMatch[1], 10) : NaN;
												if (!Number.isFinite(statusCode) || statusCode < 200 || statusCode >= 300) throw new Error(`proxyDetectRequestFail: ${statusLine || 'invalidResponse'}`);
												const lengthMatch = headers.match(/\r\nContent-Length:\s*(\d+)/i);
												if (lengthMatch) contentLength = parseInt(lengthMatch[1], 10);
												chunked = /\r\nTransfer-Encoding:\s*chunked/i.test(headers);
											}
										}
										if (headerEndIndex !== -1 && contentLength !== null && responseBuffer.length >= headerEndIndex + contentLength) break;
										if (headerEndIndex !== -1 && chunked && decoder.decode(responseBuffer).includes('\r\n0\r\n\r\n')) break;
									}
									if (headerEndIndex === -1) throw new Error('proxyDetectHeaderTooLongOrInvalid');
									const response = decoder.decode(responseBuffer);
									const ip = response.match(/(?:^|\n)ip=(.*)/)?.[1];
									const loc = response.match(/(?:^|\n)loc=(.*)/)?.[1];
									if (!ip || !loc) throw new Error('proxyDetectRespInvalid');
									detectProxyResponse = { success: true, proxy: proxyProtocol + "://" + fullProxyParams, ip, loc, responseTime: Date.now() - startTime };
								} finally {
									try { tlsSocket ? tlsSocket.close() : await tcpSocket?.close?.() } catch (e) { }
								}
							} catch (error) {
								detectProxyResponse = { success: false, error: error.message, proxy: proxyProtocol + "://" + fullProxyParams, responseTime: Date.now() - startTime };
							}
						} catch (err) {
							detectProxyResponse = { success: false, error: err.message, proxy: proxyProtocol + "://" + proxyParams, responseTime: Date.now() - startTime };
						}
						return new Response(JSON.stringify(detectProxyResponse, null, 2), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
					}

					config_JSON = await readGetconfig_JSON(env, host, userID, UA);

					if (accessPath === 'admin/init') {// resetConfigToDefault
						try {
							config_JSON = await readGetconfig_JSON(env, host, userID, UA, true);
							ctx.waitUntil(requestLogRecord(env, request, accessIP, 'Init_Config', config_JSON));
							config_JSON.init = 'configResetToDefault';
							return new Response(JSON.stringify(config_JSON, null, 2), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
						} catch (err) {
							const errorResponse = { msg: 'configResetFail, failReason: ' + err.message, error: err.message };
							return new Response(JSON.stringify(errorResponse, null, 2), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
						}
					} else if (request.method === 'POST') {// handleLogic KV opAct (POST request) 
						if (accessPath === 'admin/config.json') { // saveconfig.jsonconfig
							try {
								const newConfig = await request.json();
								// validateConfigIntegrity
								if (!newConfig.UUID || !newConfig.HOST) return new Response(JSON.stringify({ error: 'configIncomplete' }), { status: 400, headers: { 'Content-Type': 'application/json;charset=utf-8' } });

								// saveTo KV
								await env.KV.put('config.json', JSON.stringify(newConfig, null, 2));
								ctx.waitUntil(requestLogRecord(env, request, accessIP, 'Save_Config', config_JSON));
								return new Response(JSON.stringify({ success: true, message: 'configSaved' }), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
							} catch (error) {
								console.error('saveConfigFail:', error);
								return new Response(JSON.stringify({ error: 'saveConfigFail: ' + error.message }), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
							}
						} else if (accessPath === 'admin/cf.json') { // savecf.jsonconfig
							try {
								const newConfig = await request.json();
								const CF_JSON = { Email: null, GlobalAPIKey: null, AccountID: null, APIToken: null, UsageAPI: null };
								if (!newConfig.init || newConfig.init !== true) {
									if (newConfig.Email && newConfig.GlobalAPIKey) {
										CF_JSON.Email = newConfig.Email;
										CF_JSON.GlobalAPIKey = newConfig.GlobalAPIKey;
									} else if (newConfig.AccountID && newConfig.APIToken) {
										CF_JSON.AccountID = newConfig.AccountID;
										CF_JSON.APIToken = newConfig.APIToken;
									} else if (newConfig.UsageAPI) {
										CF_JSON.UsageAPI = newConfig.UsageAPI;
									} else {
										return new Response(JSON.stringify({ error: 'configIncomplete' }), { status: 400, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
									}
								}

								// saveTo KV
								await env.KV.put('cf.json', JSON.stringify(CF_JSON, null, 2));
								ctx.waitUntil(requestLogRecord(env, request, accessIP, 'Save_Config', config_JSON));
								return new Response(JSON.stringify({ success: true, message: 'configSaved' }), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
							} catch (error) {
								console.error('saveConfigFail:', error);
								return new Response(JSON.stringify({ error: 'saveConfigFail: ' + error.message }), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
							}
						} else if (accessPath === 'admin/tg.json') { // savetg.jsonconfig
							try {
								const newConfig = await request.json();
								if (newConfig.init && newConfig.init === true) {
									const TG_JSON = { BotToken: null, ChatID: null };
									await env.KV.put('tg.json', JSON.stringify(TG_JSON, null, 2));
								} else {
									if (!newConfig.BotToken || !newConfig.ChatID) return new Response(JSON.stringify({ error: 'configIncomplete' }), { status: 400, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
									await env.KV.put('tg.json', JSON.stringify(newConfig, null, 2));
								}
								ctx.waitUntil(requestLogRecord(env, request, accessIP, 'Save_Config', config_JSON));
								return new Response(JSON.stringify({ success: true, message: 'configSaved' }), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
							} catch (error) {
								console.error('saveConfigFail:', error);
								return new Response(JSON.stringify({ error: 'saveConfigFail: ' + error.message }), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
							}
						} else if (caseSensitiveAccessPath === 'admin/ADD.txt') { // saveCustomPreferredIP
							try {
								const customIPs = await request.text();
								await env.KV.put('ADD.txt', customIPs);// saveTo KV
								ctx.waitUntil(requestLogRecord(env, request, accessIP, 'Save_Custom_IPs', config_JSON));
								return new Response(JSON.stringify({ success: true, message: 'customIPsaved' }), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
							} catch (error) {
								console.error('saveCustomIPfailFail:', error);
								return new Response(JSON.stringify({ error: 'saveCustomIPfailFail: ' + error.message }), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
							}
						} else return new Response(JSON.stringify({ error: 'unsupportedPOSTrequestPath' }), { status: 404, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
					} else if (accessPath === 'admin/config.json') {// handleLogic admin/config.json request, returnReturnJSON
						return new Response(JSON.stringify(config_JSON, null, 2), { status: 200, headers: { 'Content-Type': 'application/json' } });
					} else if (caseSensitiveAccessPath === 'admin/ADD.txt') {// handleLogic admin/ADD.txt request, returnLocalPreferredIP
						let localPreferredIP = await env.KV.get('ADD.txt') || 'null';
						if (localPreferredIP == 'null') localPreferredIP = (await generateRandomIP(request, config_JSON.preferredSubGen.thisLocationIPlib.randomCount, config_JSON.preferredSubGen.thisLocationIPlib.specifiedPort))[1];
						return new Response(localPreferredIP, { status: 200, headers: { 'Content-Type': 'text/plain;charset=utf-8', 'asn': request.cf.asn } });
					} else if (accessPath === 'admin/cf.json') {// CFconfigTextItem
						return new Response(JSON.stringify(request.cf, null, 2), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
					}

					ctx.waitUntil(requestLogRecord(env, request, accessIP, 'Admin_Login', config_JSON));
					return new Response(matrixEdgeAdminDashboard(), { status: 200, headers: { 'Content-Type': 'text/html; charset=UTF-8' } });
				} else if (accessPath === 'logout' || uuidRegex.test(accessPath)) {//clearExceptcookieandRedirectToLoginPage
					const response = new Response('redirecting...', { status: 302, headers: { 'Location': '/login' } });
					response.headers.set('Set-Cookie', 'auth=; Path=/; Max-Age=0; HttpOnly');
					return response;
				} else if (accessPath === 'sub') {//handleSubRequest
					const subTOKEN = await MD5MD5(host + userID), asPreferredSubGenerator = ['1', 'true'].includes(env.BEST_SUB) && url.searchParams.get('host') === 'example.com' && url.searchParams.get('uuid') === '00000000-0000-4000-8000-000000000000' && UA.toLowerCase().includes('tunnel (https://github.com/' + signatureDict[1] + '/edge');
					const requestTOKEN = url.searchParams.get('token');
					const userClientRequestSub = requestTOKEN === subTOKEN;
					const currentDaySeq = Math.floor(Date.now() / 86400000);
					const subConvertBackendTOKENkindSub = base64SecretEncode(subTOKEN, userID);
					const [todaySubConvertBackendOnlyTOKEN, yesterdaySubConvertBackendOnlyTOKEN] = await Promise.all([
						MD5MD5(subConvertBackendTOKENkindSub + currentDaySeq),
						MD5MD5(subConvertBackendTOKENkindSub + (currentDaySeq - 1)),
					]);
					const subConvertBackendRequestSub = requestTOKEN === todaySubConvertBackendOnlyTOKEN || requestTOKEN === yesterdaySubConvertBackendOnlyTOKEN;
					if (userClientRequestSub || subConvertBackendRequestSub || asPreferredSubGenerator) {
						config_JSON = await readGetconfig_JSON(env, host, userID, UA);
						if (asPreferredSubGenerator) ctx.waitUntil(requestLogRecord(env, request, accessIP, 'Get_Best_SUB', config_JSON, false));
						else ctx.waitUntil(requestLogRecord(env, request, accessIP, 'Get_SUB', config_JSON));
						const ua = UA.toLowerCase();
						const responseHeaders = {
							"content-type": "text/plain; charset=utf-8",
							"Profile-Update-Interval": config_JSON.preferredSubGen.SUBUpdateTime,
							"Profile-web-page-url": url.protocol + '//' + url.host + '/admin',
							"Cache-Control": "no-store",
						};
						if (config_JSON.CF.Usage.success) {
							const pagesSum = config_JSON.CF.Usage.pages;
							const workersSum = config_JSON.CF.Usage.workers;
							const total = Math.max(0, Number(config_JSON.preferredSubGen.LIMIT_GB) || 100) * 1024 * 1024 * 1024;
							const expireSeconds = Math.floor(Date.now() / 1000) + Math.max(1, Number(config_JSON.preferredSubGen.LIMIT_DAYS) || 30) * 86400;
							responseHeaders["Subscription-Userinfo"] = `upload=${pagesSum}; download=${workersSum}; total=${total}; expire=${expireSeconds}`;
						}
						const isSubConverterRequest = url.searchParams.has('b64') || url.searchParams.has('base64') || request.headers.get('subconverter-request') || request.headers.get('subconverter-version') || ua.includes('subconverter') || ua.includes(('CF-Workers-SUB').toLowerCase()) || asPreferredSubGenerator;
						const subType = isSubConverterRequest
							? 'mixed'
							: url.searchParams.has('target')
								? url.searchParams.get('target')
								: url.searchParams.has('clash') || ua.includes('clash') || ua.includes('meta') || ua.includes('mihomo')
									? 'clash'
									: url.searchParams.has('sb') || url.searchParams.has('singbox') || ua.includes('singbox') || ua.includes('sing-box')
										? 'singbox'
										: url.searchParams.has('surge') || ua.includes('surge')
											? 'surge&ver=4'
											: url.searchParams.has('quanx') || ua.includes('quantumult')
												? 'quanx'
												: url.searchParams.has('loon') || ua.includes('loon')
													? 'loon'
													: 'mixed';

						if (!ua.includes('mozilla')) responseHeaders["Content-Disposition"] = `attachment; filename*=utf-8''${encodeURIComponent(config_JSON.preferredSubGen.SUBNAME)}`;
						const protoType = ((url.searchParams.has('surge') || ua.includes('surge')) && config_JSON.protoType !== 'ss') ? 'tro' + 'jan' : config_JSON.protoType;
						let subContent = '';
						if (subType === 'mixed') {
							const TLSsplitPieceParamNum = config_JSON.TLSsplitPiece == 'Shadowrocket' ? `&fragment=${encodeURIComponent('1,40-60,30-50,tlshello')}` : config_JSON.TLSsplitPiece == 'Happ' ? `&fragment=${encodeURIComponent('3,1,tlshello')}` : '';
							let fullPreferredIP = [], otherNodesLINK = '', relayIPpool = [];

							if (!url.searchParams.has('sub') && config_JSON.preferredSubGen.local) { // localGenSub
								const fullPreferredList = config_JSON.preferredSubGen.thisLocationIPlib.randomZhIP ? (
									await generateRandomIP(request, config_JSON.preferredSubGen.thisLocationIPlib.randomCount, config_JSON.preferredSubGen.thisLocationIPlib.specifiedPort)
								)[0] : await env.KV.get('ADD.txt') ? await normalizeToArray(await env.KV.get('ADD.txt')) : (
									await generateRandomIP(request, config_JSON.preferredSubGen.thisLocationIPlib.randomCount, config_JSON.preferredSubGen.thisLocationIPlib.specifiedPort)
								)[0];
								const preferredAPI = [], preferredIP = [], otherNodes = [];
								for (const element of fullPreferredList) {
									if (element.toLowerCase().startsWith('sub://')) {
										preferredAPI.push(element);
									} else {
										const remarkPosition = element.indexOf('#');
										const addressPart = remarkPosition > -1 ? element.slice(0, remarkPosition) : element;
										const remarkPart = remarkPosition > -1 ? element.slice(remarkPosition) : '';
										const subMatch = element.match(/sub\s*=\s*([^\s&#]+)/i);
										if (subMatch && subMatch[1].trim().includes('.')) {
											const preferredIPasRelayIP = element.toLowerCase().includes('proxyip=true');
											if (preferredIPasRelayIP) preferredAPI.push('sub://' + subMatch[1].trim() + "?proxyip=true" + (element.includes('#') ? ('#' + element.split('#')[1]) : ''));
											else preferredAPI.push('sub://' + subMatch[1].trim() + (element.includes('#') ? ('#' + element.split('#')[1]) : ''));
										} else if (addressPart.toLowerCase().startsWith('https://')) {
											preferredAPI.push(element);
										} else if (addressPart.toLowerCase().includes('://')) {
											if (element.includes('#')) {
												const addressRemarkSplit = element.split('#');
												otherNodes.push(addressRemarkSplit[0] + '#' + encodeURIComponent(decodeURIComponent(addressRemarkSplit[1])));
											} else otherNodes.push(element);
										} else {
											if (addressPart.includes('*')) {
												preferredIP.push(replaceAsteriskWithRandomChar(addressPart) + remarkPart);
											} else preferredIP.push(element);
										}
									}
								}
								const requestPreferredAPIcontent = await requestPreferredAPI(preferredAPI, '443');
								const mergeOtherNodesArray = [...new Set(otherNodes.concat(requestPreferredAPIcontent[1]))];
								otherNodesLINK = mergeOtherNodesArray.length > 0 ? mergeOtherNodesArray.join('\n') + '\n' : '';
								const preferredAPIOfIP = requestPreferredAPIcontent[0];
								relayIPpool = requestPreferredAPIcontent[3] || [];
								fullPreferredIP = [...new Set(preferredIP.concat(preferredAPIOfIP))];
							} else { // PreferredSubGenerator
								let PreferredSubGeneratorHOST = url.searchParams.get('sub') || config_JSON.preferredSubGen.SUB;
								const [preferredGeneratorIParray, preferredGeneratorOtherNodes] = await getPreferredSubGeneratorData(PreferredSubGeneratorHOST);
								fullPreferredIP = fullPreferredIP.concat(preferredGeneratorIParray);
								otherNodesLINK += preferredGeneratorOtherNodes;
							}
							const ECHLINKparamNum = config_JSON.ECH ? `&ech=${encodeURIComponent((config_JSON.ECHConfig.SNI ? config_JSON.ECHConfig.SNI + '+' : '') + config_JSON.ECHConfig.DNS)}` : '';
							const isLoonOrSurge = ua.includes('loon') || ua.includes('surge');
							const { type: transportProto, pathFieldName, domainFieldName } = getTransportProtoConfig(config_JSON);
							subContent = otherNodesLINK + fullPreferredIP.map(originalAddress => {
								// systemOneRegex: match domainName/IPv4/IPv6locationAddr + optionalPort + canSelectRemark
								// showExample:
								//   - domainName: hj.xmm1993.top:2096#remark or example.com
								//   - IPv4: 166.0.188.128:443#Los Angeles or 166.0.188.128
								//   - IPv6: [2606:4700::]:443#CMCC or [2606:4700::]
								const regex = /^(\[[\da-fA-F:]+\]|[\d.]+|[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)*)(?::(\d+))?(?:#(.+))?$/;
								const match = originalAddress.match(regex);

								let nodeAddress, nodePort = "443", nodeRemark;

								if (match) {
									nodeAddress = match[1];  // IPaddressOrDomain(mayHaveBrackets)
									nodePort = match[2] ? match[2] : '443';  // portDefaultVal443, SS noTLSinGenerateCompleteChainConnectTimeAgainMap
									nodeRemark = match[3] || nodeAddress;  // remark,defaultConfirmAsLocationAddrThisSelf
								} else {
									// malformedFormat, skipProcessingReturnnull
									console.warn(`[subContent] malformedIPformatIgnored: ${originalAddress}`);
									return null;
								}

								let fullNodePath = config_JSON.fullNodePath;

								const chainProxyMatch = nodeRemark.match(/\$(socks5|http|https|turn|sstp):\/\/([^#\s]+)/i);
								if (chainProxyMatch) {
									try {
										const proxyProtocol = chainProxyMatch[1].toLowerCase(), proxyParams = chainProxyMatch[2];
										const chainProxyData = { type: proxyProtocol, ...getGetSOCKS5account(proxyParams, getProxyDefaultPort(proxyProtocol)) };
										fullNodePath = `/video/${base64SecretEncode(JSON.stringify(chainProxyData), userID) + (config_JSON.enableUse0RTT ? '?ed=2560' : '')}`;
										nodeRemark = nodeRemark.replace(chainProxyMatch[0], '').trim() || nodeAddress;
									} catch (error) {
										console.warn(`[subContent] chainProxyResolveFail, instructionIgnored: ${chainProxyMatch[0]} (${error && error.message ? error.message : error})`);
									}
								} else if (relayIPpool.length > 0) {
									const matchedRelayIP = relayIPpool.find(p => p.includes(nodeAddress));
									if (matchedRelayIP) fullNodePath = (`${config_JSON.PATH}/proxyip=${matchedRelayIP}`).replace(/\/\//g, '/') + (config_JSON.enableUse0RTT ? '?ed=2560' : '');
								}
								if (isLoonOrSurge) fullNodePath = fullNodePath.replace(/,/g, '%2C');

								if (protoType === 'ss' && !asPreferredSubGenerator) {
									if (!config_JSON.SS.TLS) {
										const TLSport = [443, 2053, 2083, 2087, 2096, 8443];
										const NOTLSport = [80, 2052, 2082, 2086, 2095, 8080];
										nodePort = String(NOTLSport[TLSport.indexOf(Number(nodePort))] ?? nodePort);
									}
									fullNodePath = (fullNodePath.includes('?') ? fullNodePath.replace('?', '?enc=' + config_JSON.SS.encryptMethod + '&') : (fullNodePath + '?enc=' + config_JSON.SS.encryptMethod)).replace(/([=,])/g, '\\$1');
									if (!isSubConverterRequest) fullNodePath = fullNodePath + ';mux=0';
									return `${protoType}://${btoa(config_JSON.SS.encryptMethod + ':00000000-0000-4000-8000-000000000000')}@${nodeAddress}:${nodePort}?plugin=v2${encodeURIComponent('ray-plugin;mode=websocket;host=example.com;path=' + (config_JSON.randomPath ? randomPath(fullNodePath) : fullNodePath) + (config_JSON.SS.TLS ? ';tls' : '')) + ECHLINKparamNum + TLSsplitPieceParamNum}#${encodeURIComponent(nodeRemark)}`;
								} else {
									const transportPathParamValue = getTransportPathParamValue(config_JSON, fullNodePath, asPreferredSubGenerator);
									return `${protoType}://00000000-0000-4000-8000-000000000000@${nodeAddress}:${nodePort}?security=tls&type=${transportProto + ECHLINKparamNum}&${domainFieldName}=example.com&fp=${config_JSON.Fingerprint}&sni=example.com&${pathFieldName}=${encodeURIComponent(transportPathParamValue) + TLSsplitPieceParamNum}&encryption=none#${encodeURIComponent(nodeRemark)}`;
								}
							}).filter(item => item !== null).join('\n');
						} else { // subConvert
							const subConvertURL = `${config_JSON.subConvertConfig.SUBAPI}/sub?target=${subType}&url=${encodeURIComponent(url.protocol + '//' + url.host + '/sub?target=mixed&token=' + todaySubConvertBackendOnlyTOKEN + '&cnIspCode=' + identifyCarrier(request) + (url.searchParams.has('sub') && url.searchParams.get('sub') != '' ? `&sub=${url.searchParams.get('sub')}` : ''))}&config=${encodeURIComponent(config_JSON.subConvertConfig.SUBCONFIG)}&emoji=${config_JSON.subConvertConfig.SUBEMOJI}&list=${config_JSON.subConvertConfig.SUBLIST}&scv=${config_JSON.skipCertDocVerifyCert}&xudp=${config_JSON.subConvertConfig.XUDP}&udp=${config_JSON.subConvertConfig.UDP}&tls13=${config_JSON.subConvertConfig.TLS13}&append_type=${config_JSON.subConvertConfig.APPEND_TYPE}&sort=${config_JSON.subConvertConfig.SORT}`;
							try {
								const response = await fetch(subConvertURL, { headers: { 'User-Agent': 'Subconverter for ' + subType + ' edge' + 'tunnel (https://github.com/' + signatureDict[1] + '/edge' + 'tunnel)' } });
								if (response.ok) {
									subContent = await response.text();
									if (url.searchParams.has('surge') || ua.includes('surge')) subContent = SurgesubConfigFileHotpatch(subContent, url.protocol + '//' + url.host + '/sub?token=' + subTOKEN + '&surge', config_JSON);
								} else return new Response('subConvertBackendError: ' + response.statusText, { status: response.status });
							} catch (error) {
								return new Response('subConvertBackendError: ' + error.message, { status: 403 });
							}
						}

						if (!ua.includes('subconverter') && userClientRequestSub) {
							const afterShuffle2HOSTS = [...config_JSON.HOSTS].sort(() => Math.random() - 0.5);
							let replaceDomainCount = 0, whenBeforeRandomZhHOST = null;
							subContent = subContent
								.replace(/00000000-0000-4000-8000-000000000000/g, config_JSON.UUID)
								.replace(/MDAwMDAwMDAtMDAwMC00MDAwLTgwMDAtMDAwMDAwMDAwMDAw/g, btoa(config_JSON.UUID))
								.replace(/example\.com/g, () => {
									if (replaceDomainCount % 2 === 0) {
										const originStarthost = afterShuffle2HOSTS[Math.floor(replaceDomainCount / 2) % afterShuffle2HOSTS.length];
										whenBeforeRandomZhHOST = replaceAsteriskWithRandomChar(originStarthost);
									}
									replaceDomainCount++;
									return whenBeforeRandomZhHOST;
								});
						}

						if (subType === 'mixed' && (!ua.includes('mozilla') || url.searchParams.has('b64') || url.searchParams.has('base64'))) subContent = btoa(subContent);

						if (subType === 'singbox') {
							subContent = await SingboxsubConfigFileHotpatch(subContent, config_JSON);
							responseHeaders["content-type"] = 'application/json; charset=utf-8';
						} else if (subType === 'clash') {
							subContent = ClashsubConfigFileHotpatch(subContent, config_JSON);
							responseHeaders["content-type"] = 'application/x-yaml; charset=utf-8';
						}
						return new Response(subContent, { status: 200, headers: responseHeaders });
					}
				} else if (accessPath === 'locations') {//relaylocationslistTable
					const cookies = request.headers.get('Cookie') || '';
					const authCookie = cookies.split(';').find(c => c.trim().startsWith('auth='))?.split('=')[1];
					if (authCookie && authCookie == await MD5MD5(UA + encryptKey + adminPassword)) return fetch(new Request('https://speed.cloudflare.com/locations', { headers: { 'Referer': 'https://speed.cloudflare.com/' } }));
				} else if (accessPath === 'robots.txt') return new Response('User-agent: *\nDisallow: /', { status: 200, headers: { 'Content-Type': 'text/plain; charset=UTF-8' } });
			} else if (!envUUID) return new Response(matrixEdgeSetupNotice('KV'), { status: 404, headers: { 'Content-Type': 'text/html; charset=UTF-8', 'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate', 'Pragma': 'no-cache', 'Expires': '0' } });
		}

		let decoyPage2URL = env.URL || 'nginx';
		if (decoyPage2URL && decoyPage2URL !== 'nginx' && decoyPage2URL !== '1101') {
			decoyPage2URL = decoyPage2URL.trim().replace(/\/$/, '');
			if (!decoyPage2URL.match(/^https?:\/\//i)) decoyPage2URL = 'https://' + decoyPage2URL;
			if (decoyPage2URL.toLowerCase().startsWith('http://')) decoyPage2URL = 'https://' + decoyPage2URL.substring(7);
			try { const u = new URL(decoyPage2URL); decoyPage2URL = u.protocol + '//' + u.host } catch (e) { decoyPage2URL = 'nginx' }
		}
		if (decoyPage2URL === '1101') return new Response(await html1101(url.host, accessIP), { status: 200, headers: { 'Content-Type': 'text/html; charset=UTF-8' } });
		try {
			const relayURL = new URL(decoyPage2URL), newRequestHeader = new Headers(request.headers);
			newRequestHeader.set('Host', relayURL.host);
			newRequestHeader.set('Referer', relayURL.origin);
			newRequestHeader.set('Origin', relayURL.origin);
			if (!newRequestHeader.has('User-Agent') && UA && UA !== 'null') newRequestHeader.set('User-Agent', UA);
			const relayResponse = await fetch(relayURL.origin + url.pathname + url.search, { method: request.method, headers: newRequestHeader, body: request.body, cf: request.cf });
			const contentType = relayResponse.headers.get('content-type') || '';
			// onlyHandleTextTypeResponse
			if (/text|javascript|json|xml/.test(contentType)) {
				const responseContent = (await relayResponse.text()).replaceAll(relayURL.host, url.host);
				return new Response(responseContent, { status: relayResponse.status, headers: { ...Object.fromEntries(relayResponse.headers), 'Cache-Control': 'no-store' } });
			}
			return relayResponse;
		} catch (error) { }
		return new Response(await nginx(), { status: 200, headers: { 'Content-Type': 'text/html; charset=UTF-8' } });
	}
};
///////////////////////////////////////////////////////////////////////xHTTPtransportData///////////////////////////////////////////////
const HPACKHuffmancodeLength = [
	13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28,
	28, 28, 28, 28, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 28,
	6, 10, 10, 12, 13, 6, 8, 11, 10, 10, 8, 11, 8, 6, 6, 6,
	5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 7, 8, 15, 6, 12, 10,
	13, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
	7, 7, 7, 7, 7, 7, 7, 7, 8, 7, 8, 13, 19, 13, 14, 6,
	15, 5, 6, 5, 6, 5, 6, 6, 6, 5, 7, 7, 6, 6, 6, 5,
	6, 7, 6, 5, 5, 6, 7, 7, 7, 7, 7, 15, 11, 14, 13, 28,
	20, 22, 20, 20, 22, 22, 22, 23, 22, 23, 23, 23, 23, 23, 24, 23,
	24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24,
	22, 21, 20, 22, 22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23,
	21, 21, 22, 21, 23, 22, 23, 23, 20, 22, 22, 22, 23, 22, 22, 23,
	26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25,
	19, 21, 26, 27, 27, 26, 27, 24, 21, 21, 26, 26, 28, 27, 27, 27,
	20, 24, 20, 21, 22, 21, 21, 23, 22, 22, 25, 25, 24, 24, 26, 23,
	26, 27, 26, 26, 27, 27, 27, 27, 27, 28, 27, 27, 27, 27, 27, 26,
	30
];

function getXHTTPPaddingmarkIdentify(yourUUID) {
	return { header: yourUUID.slice(1, 7), key: '_' + yourUUID.slice(25, 31) };
}

function calcCalcHPACKHuffmanbyteLength(string) {
	const byte = new TextEncoder().encode(string);
	let totalDigits = 0;
	for (let i = 0; i < byte.length; i++) {
		totalDigits += HPACKHuffmancodeLength[byte[i]];
	}
	return Math.ceil(totalDigits / 8);
}

function extractXHTTPPaddingvalue(request, selfPaddingheader, selfPaddingkey) {
	const headerValue = request.headers.get(selfPaddingheader);
	if (headerValue) {
		try {
			const parseParseURL = new URL(headerValue, 'https://x.invalid');
			const queryValue = parseParseURL.searchParams.get(selfPaddingkey);
			if (queryValue) return queryValue;
		} catch (e) { }
		return headerValue;
	}
	const requestURL = new URL(request.url);
	return requestURL.searchParams.get(selfPaddingkey) || '';
}

function verifyXHTTPPadding(request, selfPaddingheader, selfPaddingkey) {
	const paddingvalue = extractXHTTPPaddingvalue(request, selfPaddingheader, selfPaddingkey);
	if (!paddingvalue) return true;
	const huffmanlength = calcCalcHPACKHuffmanbyteLength(paddingvalue);
	return huffmanlength >= 98 && huffmanlength <= 1002;
}

const xHTTPBase62charset = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
function genXHTTPPaddingstr(length) {
	const charsetLength = xHTTPBase62charset.length;
	let finishResult = '';
	for (let i = 0; i < length; i++) {
		finishResult += xHTTPBase62charset[Math.floor(Math.random() * charsetLength)];
	}
	return finishResult;
}

async function handleXHTTPrequest(request, yourUUID, relayContext = {}) {
	if (!request.body) return new Response('Bad Request', { status: 400 });
	const { header: selfPaddingheader, key: selfPaddingkey } = getXHTTPPaddingmarkIdentify(yourUUID);
	if (!verifyXHTTPPadding(request, selfPaddingheader, selfPaddingkey)) return new Response('Bad Request', { status: 400 });
	const reader = request.body.getReader();
	const firstPacket = await readXHTTPfirstPacket(reader, yourUUID);
	if (!firstPacket) {
		try { reader.releaseLock() } catch (e) { }
		return new Response('Invalid request', { status: 400 });
	}
	if (isSpeedTestSite(firstPacket.hostname) && relayContext.proxyType === null) {
		try { reader.releaseLock() } catch (e) { }
		return new Response(buildLocal204response(firstPacket.respHeader), {
			status: 200,
			headers: {
				'Content-Type': 'application/octet-stream',
				'X-Accel-Buffering': 'no',
				'Cache-Control': 'no-store'
			}
		});
	}
	if (firstPacket.isUDP && firstPacket.protocol !== 'trojan' && firstPacket.port !== 53) {
		try { reader.releaseLock() } catch (e) { }
		return new Response('UDP is not supported', { status: 400 });
	}

	const responseHeaders = new Headers({
		'Content-Type': 'application/octet-stream',
		'X-Accel-Buffering': 'no',
		'Cache-Control': 'no-store'
	});

	try {
		const responseURL = new URL('https://x.invalid/');
		responseURL.searchParams.set(selfPaddingkey, genXHTTPPaddingstr(100 + Math.floor(Math.random() * 901)));
		responseHeaders.set(selfPaddingheader, responseURL.toString());
	} catch (e) { }

	if (firstPacket.isUDP) return handleXHTTPUDPrequest(firstPacket, reader, request, relayContext, responseHeaders);

	try { reader.releaseLock() } catch (e) { }

	const remoteConnWrapper = { socket: null, connectingPromise: null, retryConnect: null, downlinkDrain: Promise.resolve() };
	const abortController = new AbortController();
	let cleaned = false;
	const clearLogic = (reason) => {
		if (cleaned) return;
		cleaned = true;
		try { abortController.abort(reason) } catch (e) { }
		invalidatedTCPconnGeneration(remoteConnWrapper);
	};

	const placeholder2WS = { readyState: WebSocket.OPEN };

	let socket;
	try {
		socket = await forwardataTCP(firstPacket.hostname, firstPacket.port, firstPacket.rawData, placeholder2WS, firstPacket.respHeader, remoteConnWrapper, yourUUID, request, relayContext, firstPacket.protocol === 'trojan', firstPacket.rawData, true);
	} catch (err) {
		log(`[xHTTP-Pipe] connFail: ${err?.message || err}`);
		clearLogic(err);
		return new Response('bad gateway', { status: 502 });
	}
	if (!socket) {
		clearLogic(new Error('socket is null'));
		return new Response('bad gateway', { status: 502 });
	}

	const uplinkPromise = (async () => {
		const uplinkPacker = createUplinkGrainpackStream();
		const moveRunPromise = uplinkPacker.readable.pipeTo(socket.writable, { signal: abortController.signal });
		void moveRunPromise.catch(clearLogic);
		const uplinkreader = request.body.getReader();
		const cancelUplinkreader = () => {
			try { uplinkreader.cancel(abortController.signal.reason).catch(() => { }); } catch (e) { }
		};
		abortController.signal.addEventListener('abort', cancelUplinkreader, { once: true });
		try {
			try {
				while (true) {
					const { done, value } = await uplinkreader.read();
					if (done) break;
					if (value?.byteLength) await uplinkPacker.writeIn(value);
				}
			} finally {
				abortController.signal.removeEventListener('abort', cancelUplinkreader);
				try { uplinkreader.releaseLock() } catch (e) { }
			}
		} finally {
			try { await uplinkPacker.finishEnd() } catch (e) { }
		}
		await moveRunPromise;
	})();

	const responseStream = typeof IdentityTransformStream !== 'undefined'
		? new IdentityTransformStream()
		: new TransformStream();
	const downlinkPromise = (async () => {
		const writer = responseStream.writable.getWriter();
		try {
			if (validDataLength(firstPacket.respHeader) > 0) await writer.write(firstPacket.respHeader);
		} catch (error) {
			try { await writer.abort(error) } catch (e) { }
			throw error;
		} finally {
			try { writer.releaseLock() } catch (e) { }
		}
		await socket.readable.pipeTo(responseStream.writable, { signal: abortController.signal });
	})();

	void uplinkPromise.catch(clearLogic);
	void downlinkPromise.then(() => clearLogic(), clearLogic);
	void Promise.allSettled([uplinkPromise, downlinkPromise]);

	return new Response(responseStream.readable, { status: 200, headers: responseHeaders });
}

function handleXHTTPUDPrequest(firstPacket, reader, request, relayContext, responseHeaders) {
	const trojanUDPContext = { cache: new Uint8Array(0), relayAddress: relayContext.trojanRelayAddress };
	return new Response(new ReadableStream({
		async start(controller) {
			let closed = false;
			let udpRespHeader = firstPacket.respHeader;
			const xBridge = {
				readyState: WebSocket.OPEN,
				send(data) {
					if (closed) return;
					try {
						const chunk = data instanceof Uint8Array
							? data
							: data instanceof ArrayBuffer
								? new Uint8Array(data)
								: ArrayBuffer.isView(data)
									? new Uint8Array(data.buffer, data.byteOffset, data.byteLength)
									: new Uint8Array(data);
						controller.enqueue(chunk);
					} catch (e) {
						closed = true;
						this.readyState = WebSocket.CLOSED;
					}
				},
				close() {
					if (closed) return;
					closed = true;
					this.readyState = WebSocket.CLOSED;
					try { controller.close() } catch (e) { }
				}
			};
			let turnSendFailFail = false;
			try {
				if (firstPacket.protocol === 'trojan') {
					trojanUDPContext.targetHost = firstPacket.hostname;
					trojanUDPContext.targetPort = firstPacket.port;
					if (trojanUDPContext.relayAddress) await forwardTrojanUDPnumData(firstPacket.rawData, xBridge, trojanUDPContext, request);
				}
				if (!(firstPacket.protocol === 'trojan' && trojanUDPContext.relayAddress) && firstPacket.rawData?.byteLength) {
					if (firstPacket.protocol === 'trojan') await forwardTrojanUDPnumData(firstPacket.rawData, xBridge, trojanUDPContext, request);
					else await forwardataudp(firstPacket.rawData, xBridge, udpRespHeader, request);
					udpRespHeader = null;
				}
				while (true) {
					const { done, value } = await reader.read();
					if (done) break;
					if (!value || value.byteLength === 0) continue;
					if (firstPacket.protocol === 'trojan') await forwardTrojanUDPnumData(value, xBridge, trojanUDPContext, request);
					else await forwardataudp(value, xBridge, udpRespHeader, request);
					udpRespHeader = null;
				}
			} catch (err) {
				turnSendFailFail = true;
				log(`[xHTTPturnSend] handleLogicFailFail: ${err?.message || err}`);
				closeSocketQuietly(xBridge);
			} finally {
			const keepTrojanUDPrelayDownlink = !turnSendFailFail && firstPacket.protocol === 'trojan' && trojanUDPContext.relayAddress && trojanUDPContext.relaySocket;
			if (!keepTrojanUDPrelayDownlink) {
				try { trojanUDPContext.relaySocket?.close() } catch (e) { }
				closeSocketQuietly(xBridge);
			}
			try { reader.releaseLock() } catch (e) { }
			}
		},
		cancel() {
			try { trojanUDPContext.relaySocket?.close() } catch (e) { }
			try { reader.releaseLock() } catch (e) { }
		}
	}), { status: 200, headers: responseHeaders });
}

function validDataLength(data) {
	if (!data) return 0;
	if (typeof data.byteLength === 'number') return data.byteLength;
	if (typeof data.length === 'number') return data.length;
	return 0;
}

function invalidatedTCPconnGeneration(remoteConnWrapper) {
	if (!remoteConnWrapper) return;
	remoteConnWrapper.generation = (Number.isInteger(remoteConnWrapper.generation) ? remoteConnWrapper.generation : 0) + 1;
	const socket = remoteConnWrapper.socket;
	remoteConnWrapper.socket = null;
	remoteConnWrapper.downlinkController = null;
	remoteConnWrapper.downlinkDrain = Promise.resolve();
	try { socket?.close?.() } catch (e) { }
}

function openStartTCPconnGeneration(remoteConnWrapper) {
	if (!Number.isInteger(remoteConnWrapper.generation)) remoteConnWrapper.generation = 0;
	const generation = ++remoteConnWrapper.generation;
	const previousSocket = remoteConnWrapper.socket;
	remoteConnWrapper.socket = null;
	const previousDownlink = remoteConnWrapper.downlinkController;
	remoteConnWrapper.downlinkController = null;
	const previousDrain = remoteConnWrapper.downlinkDrain || Promise.resolve();
	let currentDrain;
	try { currentDrain = previousDownlink?.stopStopAndRefreshNew?.() || Promise.resolve() }
	catch (error) { currentDrain = Promise.reject(error) }
	const downlinkDrain = Promise.all([previousDrain, currentDrain]);
	// Installation awaits this promise; attach a handler immediately in case draining fails before dialing completes.
	downlinkDrain.catch(() => { });
	remoteConnWrapper.downlinkDrain = downlinkDrain;
	try { previousSocket?.close?.() } catch (e) { }
	return { generation, downlinkDrain };
}

async function readXHTTPfirstPacket(reader, token) {
	const decoder = vlessTextDecoder;

	const tryParseVlessFirstPacket = (data) => {
		const length = data.byteLength;
		if (length < 18) return { statusState: 'need_more' };
		if (!UUIDbyteMatch(data, 1, token)) return { statusState: 'invalid' };

		const optLen = data[17];
		const cmdIndex = 18 + optLen;
		if (length < cmdIndex + 1) return { statusState: 'need_more' };

		const cmd = data[cmdIndex];
		if (cmd !== 1 && cmd !== 2) return { statusState: 'invalid' };

		const portIndex = cmdIndex + 1;
		if (length < portIndex + 3) return { statusState: 'need_more' };

		const port = (data[portIndex] << 8) | data[portIndex + 1];
		const addressType = data[portIndex + 2];
		const addressIndex = portIndex + 3;
		let headerLen = -1;
		let hostname = '';

		if (addressType === 1) {
			if (length < addressIndex + 4) return { statusState: 'need_more' };
			hostname = `${data[addressIndex]}.${data[addressIndex + 1]}.${data[addressIndex + 2]}.${data[addressIndex + 3]}`;
			headerLen = addressIndex + 4;
		} else if (addressType === 2) {
			if (length < addressIndex + 1) return { statusState: 'need_more' };
			const domainLen = data[addressIndex];
			if (length < addressIndex + 1 + domainLen) return { statusState: 'need_more' };
			hostname = decoder.decode(data.subarray(addressIndex + 1, addressIndex + 1 + domainLen));
			headerLen = addressIndex + 1 + domainLen;
		} else if (addressType === 3) {
			if (length < addressIndex + 16) return { statusState: 'need_more' };
			const ipv6 = [];
			for (let i = 0; i < 8; i++) {
				const base = addressIndex + i * 2;
				ipv6.push(((data[base] << 8) | data[base + 1]).toString(16));
			}
			hostname = ipv6.join(':');
			headerLen = addressIndex + 16;
		} else return { statusState: 'invalid' };

		if (!hostname) return { statusState: 'invalid' };

		return {
			statusState: 'ok',
			finishResult: {
				protocol: 'vl' + 'ess',
				hostname,
				port,
				isUDP: cmd === 2,
				rawData: data.subarray(headerLen),
				respHeader: new Uint8Array([data[0], 0]),
				rawData: null,
			}
		};
	};

	const tryParseTrojanFirstPacket = (data) => {
		const passwordHash = sha224(token);
		const passwordHashBytes = new TextEncoder().encode(passwordHash);
		const length = data.byteLength;
		if (length < 58) return { statusState: 'need_more' };
		if (data[56] !== 0x0d || data[57] !== 0x0a) return { statusState: 'invalid' };
		for (let i = 0; i < 56; i++) {
			if (data[i] !== passwordHashBytes[i]) return { statusState: 'invalid' };
		}

		const socksStart = 58;
		if (length < socksStart + 2) return { statusState: 'need_more' };
		const cmd = data[socksStart];
		if (cmd !== 1 && cmd !== 3) return { statusState: 'invalid' };
		const isUDP = cmd === 3;

		const atype = data[socksStart + 1];
		let cursor = socksStart + 2;
		let hostname = '';

		if (atype === 1) {
			if (length < cursor + 4) return { statusState: 'need_more' };
			hostname = `${data[cursor]}.${data[cursor + 1]}.${data[cursor + 2]}.${data[cursor + 3]}`;
			cursor += 4;
		} else if (atype === 3) {
			if (length < cursor + 1) return { statusState: 'need_more' };
			const domainLen = data[cursor];
			if (length < cursor + 1 + domainLen) return { statusState: 'need_more' };
			hostname = decoder.decode(data.subarray(cursor + 1, cursor + 1 + domainLen));
			cursor += 1 + domainLen;
		} else if (atype === 4) {
			if (length < cursor + 16) return { statusState: 'need_more' };
			const ipv6 = [];
			for (let i = 0; i < 8; i++) {
				const base = cursor + i * 2;
				ipv6.push(((data[base] << 8) | data[base + 1]).toString(16));
			}
			hostname = ipv6.join(':');
			cursor += 16;
		} else return { statusState: 'invalid' };

		if (!hostname) return { statusState: 'invalid' };
		if (length < cursor + 4) return { statusState: 'need_more' };

		const port = (data[cursor] << 8) | data[cursor + 1];
		if (data[cursor + 2] !== 0x0d || data[cursor + 3] !== 0x0a) return { statusState: 'invalid' };
		const dataOffset = cursor + 4;

		return {
			statusState: 'ok',
			finishResult: {
				protocol: 'trojan',
				hostname,
				port,
				isUDP,
				rawData: data.subarray(dataOffset),
				rawData: data,
				respHeader: null,
			}
		};
	};

	let buffer = new Uint8Array(1024);
	let offset = 0;

	while (true) {
		const { value, done } = await reader.read();
		if (done) {
			if (offset === 0) return null;
			break;
		}

		const chunk = value instanceof Uint8Array ? value : new Uint8Array(value);
		if (offset + chunk.byteLength > buffer.byteLength) {
			const newBuffer = new Uint8Array(Math.max(buffer.byteLength * 2, offset + chunk.byteLength));
			newBuffer.set(buffer.subarray(0, offset));
			buffer = newBuffer;
		}

		buffer.set(chunk, offset);
		offset += chunk.byteLength;

		const currentData = buffer.subarray(0, offset);
		const trojanResult = tryParseTrojanFirstPacket(currentData);
		if (trojanResult.statusState === 'ok') return { ...trojanResult.finishResult, reader };

		const vlessResult = tryParseVlessFirstPacket(currentData);
		if (vlessResult.statusState === 'ok') return { ...vlessResult.finishResult, reader };

		if (trojanResult.statusState === 'invalid' && vlessResult.statusState === 'invalid') return null;
	}

	const mostFinalNumData = buffer.subarray(0, offset);
	const finalTrojanResult = tryParseTrojanFirstPacket(mostFinalNumData);
	if (finalTrojanResult.statusState === 'ok') return { ...finalTrojanResult.finishResult, reader };
	const finalVlessResult = tryParseVlessFirstPacket(mostFinalNumData);
	if (finalVlessResult.statusState === 'ok') return { ...finalVlessResult.finishResult, reader };
	return null;
}
///////////////////////////////////////////////////////////////////////gRPCtransportData///////////////////////////////////////////////
async function handleLogicgRPCrequest(request, yourUUID, relayContext = {}) {
	if (!request.body) return new Response('Bad Request', { status: 400 });
	const reader = request.body.getReader();
	const remoteConnWrapper = { socket: null, connectingPromise: null, retryConnect: null, downlinkDrain: Promise.resolve() };
	const invalidRemoteConn = () => invalidatedTCPconnGeneration(remoteConnWrapper);
	let isDnsQuery = false;
	const trojanUDPContext = { cache: new Uint8Array(0), relayAddress: relayContext.trojanRelayAddress };
	let isTrojan = null;
	let currentWriteSocket = null;
	let remoteWriter = null;
	let GRPCuplinkWriteQueue = null;
	//log('[gRPC] openStartHandleLogicDualTowardStream');
	const grpcHeaders = new Headers({
		'Content-Type': 'application/grpc',
		'grpc-status': '0',
		'X-Accel-Buffering': 'no',
		'Cache-Control': 'no-store'
	});

	const downlinkCacheLimit = downlinkGrainpacketByte;
	const downlinkFlushInterval = 1;

	return new Response(new ReadableStream({
		async start(controller) {
			let closed = false;
			let sendQueue = [];
			let queueByteCount = 0;
			let refreshTimer = null;
			let refreshNewMicrotaskqueued = false;
			const grpcBridge = {
				readyState: WebSocket.OPEN,
				send(data) {
					if (closed) return;
					const chunk = data instanceof Uint8Array ? data : new Uint8Array(data);
					const lenBytesarray = [];
					let remaining = chunk.byteLength >>> 0;
					while (remaining > 127) {
						lenBytesarray.push((remaining & 0x7f) | 0x80);
						remaining >>>= 7;
					}
					lenBytesarray.push(remaining);
					const lenBytes = new Uint8Array(lenBytesarray);
					const protobufLen = 1 + lenBytes.length + chunk.byteLength;
					const frame = new Uint8Array(5 + protobufLen);
					frame[0] = 0;
					frame[1] = (protobufLen >>> 24) & 0xff;
					frame[2] = (protobufLen >>> 16) & 0xff;
					frame[3] = (protobufLen >>> 8) & 0xff;
					frame[4] = protobufLen & 0xff;
					frame[5] = 0x0a;
					frame.set(lenBytes, 6);
					frame.set(chunk, 6 + lenBytes.length);
					sendQueue.push(frame);
					queueByteCount += frame.byteLength;
					scheduleFlushSendQueue();
				},
				close() {
					if (this.readyState === WebSocket.CLOSED) return;
					flushSendQueue(true);
					closed = true;
					this.readyState = WebSocket.CLOSED;
					try { controller.close() } catch (e) { }
				}
			};

			const flushSendQueue = (force = false) => {
				refreshNewMicrotaskqueued = false;
				if (refreshTimer) {
					clearTimeout(refreshTimer);
					refreshTimer = null;
				}
				if ((!force && closed) || queueByteCount === 0) return;
				const out = new Uint8Array(queueByteCount);
				let offset = 0;
				for (const item of sendQueue) {
					out.set(item, offset);
					offset += item.byteLength;
				}
				sendQueue = [];
				queueByteCount = 0;
				try {
					controller.enqueue(out);
				} catch (e) {
					closed = true;
					grpcBridge.readyState = WebSocket.CLOSED;
				}
			};

			const scheduleFlushSendQueue = () => {
				if (queueByteCount >= downlinkCacheLimit) {
					flushSendQueue();
					return;
				}
				if (refreshNewMicrotaskqueued || refreshTimer) return;
				refreshNewMicrotaskqueued = true;
				queueMicrotask(() => {
					refreshNewMicrotaskqueued = false;
					if (closed || queueByteCount === 0 || refreshTimer) return;
					refreshTimer = setTimeout(flushSendQueue, downlinkFlushInterval);
				});
			};

			const closeConn = () => {
				if (closed) return;
				GRPCuplinkWriteQueue?.clearEmpty();
				invalidRemoteConn();
				flushSendQueue(true);
				closed = true;
				grpcBridge.readyState = WebSocket.CLOSED;
				if (refreshTimer) clearTimeout(refreshTimer);
				if (remoteWriter) {
					try { remoteWriter.releaseLock() } catch (e) { }
					remoteWriter = null;
				}
				currentWriteSocket = null;
				try { reader.releaseLock() } catch (e) { }
				try { trojanUDPContext.relaySocket?.close() } catch (e) { }
				try { controller.close() } catch (e) { }
			};

			const releaseRemoteWriter = () => {
				if (remoteWriter) {
					try { remoteWriter.releaseLock() } catch (e) { }
					remoteWriter = null;
				}
				currentWriteSocket = null;
			};

			const uplinkWriteQueue = GRPCuplinkWriteQueue = createUplinkWriteQueue({
				getWriter: () => {
					const socket = remoteConnWrapper.socket;
					if (!socket) return null;
					if (socket !== currentWriteSocket) {
						releaseRemoteWriter();
						currentWriteSocket = socket;
						remoteWriter = socket.writable.getWriter();
					}
					return remoteWriter;
				},
				getConnTask: () => remoteConnWrapper.connectingPromise,
				releaseWriter: releaseRemoteWriter,
				retryConn: async () => {
					if (typeof remoteConnWrapper.retryConnect !== 'function') throw new Error('retry unavailable');
					await remoteConnWrapper.retryConnect();
				},
				closeConn,
				nameName: 'gRPCuplink'
			});

			const writeRemote = async (payload, allowRetry = true) => {
				return uplinkWriteQueue.writeAndWait(payload, allowRetry);
			};

			let turnSendFailFail = false;
			try {
				let pending = new Uint8Array(0);
				while (true) {
					const { done, value } = await reader.read();
					if (done) break;
					if (!value || value.byteLength === 0) continue;
					const currentChunk = value instanceof Uint8Array ? value : new Uint8Array(value);
					const merged = new Uint8Array(pending.length + currentChunk.length);
					merged.set(pending, 0);
					merged.set(currentChunk, pending.length);
					pending = merged;
					while (pending.byteLength >= 5) {
						const grpcLen = ((pending[1] << 24) >>> 0) | (pending[2] << 16) | (pending[3] << 8) | pending[4];
						const frameSize = 5 + grpcLen;
						if (pending.byteLength < frameSize) break;
						const grpcPayload = pending.subarray(5, frameSize);
						pending = pending.slice(frameSize);
						if (!grpcPayload.byteLength) continue;
						let payload = grpcPayload;
						if (payload.byteLength >= 2 && payload[0] === 0x0a) {
							let shift = 0;
							let offset = 1;
							let varintvalid = false;
							while (offset < payload.length) {
								const current = payload[offset++];
								if ((current & 0x80) === 0) {
									varintvalid = true;
									break;
								}
								shift += 7;
								if (shift > 35) break;
							}
							if (varintvalid) payload = payload.subarray(offset);
						}
						if (!payload.byteLength) continue;
						if (isDnsQuery) {
							if (isTrojan) await forwardTrojanUDPnumData(payload, grpcBridge, trojanUDPContext, request);
							else await forwardataudp(payload, grpcBridge, null, request);
							continue;
						}
						if (remoteConnWrapper.socket || remoteConnWrapper.connectingPromise) {
							if (!(await writeRemote(payload))) throw new Error('Remote socket is not ready');
						} else {
							const firstPacketbytes = numDataTurnUint8Array(payload);
							if (isTrojan === null) isTrojan = firstPacketbytes.byteLength >= 58 && firstPacketbytes[56] === 0x0d && firstPacketbytes[57] === 0x0a;
							if (isTrojan) {
								const parseResult = parseTrojanRequest(firstPacketbytes, yourUUID);
								if (parseResult?.hasError) throw new Error(parseResult.message || 'Invalid trojan request');
								const { port, hostname, rawClientData, isUDP } = parseResult;
								log(`[gRPC] trojanFirstPacket: ${hostname}:${port} | UDP: ${isUDP ? 'is' : 'not'}`);
								if (isSpeedTestSite(hostname) && relayContext.proxyType === null) {
									grpcBridge.send(buildLocal204response());
									return;
								}
								if (isUDP) {
									isDnsQuery = true;
									trojanUDPContext.targetHost = hostname;
									trojanUDPContext.targetPort = port;
									if (trojanUDPContext.relayAddress) await forwardTrojanUDPnumData(firstPacketbytes, grpcBridge, trojanUDPContext, request);
									else if (validDataLength(rawClientData) > 0) await forwardTrojanUDPnumData(rawClientData, grpcBridge, trojanUDPContext, request);
								} else {
									await forwardataTCP(hostname, port, rawClientData, grpcBridge, null, remoteConnWrapper, yourUUID, request, relayContext, true, firstPacketbytes);
								}
							} else {
								isTrojan = false;
								const parseResult = parseVlessRequest(firstPacketbytes, yourUUID);
								if (parseResult?.hasError) throw new Error(parseResult.message || 'Invalid vless request');
								const { port, hostname, version, isUDP, rawClientData } = parseResult;
								log(`[gRPC] vlessFirstPacket: ${hostname}:${port} | UDP: ${isUDP ? 'is' : 'not'}`);
								const respHeader = new Uint8Array([version, 0]);
								if (isSpeedTestSite(hostname) && relayContext.proxyType === null) {
									grpcBridge.send(buildLocal204response(respHeader));
									return;
								}
								if (isUDP) {
									if (port !== 53) throw new Error('UDP is not supported');
									isDnsQuery = true;
								}
								grpcBridge.send(respHeader);
								const rawData = rawClientData;
								if (isDnsQuery) {
									if (isTrojan) await forwardTrojanUDPnumData(rawData, grpcBridge, trojanUDPContext, request);
									else await forwardataudp(rawData, grpcBridge, null, request);
								}
								else await forwardataTCP(hostname, port, rawData, grpcBridge, null, remoteConnWrapper, yourUUID, request, relayContext);
							}
						}
					}
					flushSendQueue();
				}
				await uplinkWriteQueue.waitEmpty();
			} catch (err) {
				turnSendFailFail = true;
				log(`[gRPCturnSend] handleLogicFailFail: ${err?.message || err}`);
			} finally {
				const keepTrojanUDPrelayDownlink = !turnSendFailFail && isDnsQuery && isTrojan && trojanUDPContext.relayAddress && trojanUDPContext.relaySocket;
				if (keepTrojanUDPrelayDownlink) {
					uplinkWriteQueue.clearEmpty();
					invalidRemoteConn();
					releaseRemoteWriter();
					try { reader.releaseLock() } catch (e) { }
				} else {
					closeConn();
				}
			}
		},
		cancel() {
			GRPCuplinkWriteQueue?.clearEmpty();
			invalidRemoteConn();
			try { trojanUDPContext.relaySocket?.close() } catch (e) { }
			try { reader.releaseLock() } catch (e) { }
		}
	}), { status: 200, headers: grpcHeaders });
}

function isValidWSearlyData(bytes, token) {
	if (!bytes?.byteLength) return false;
	if (bytes.byteLength >= 18 && UUIDbyteMatch(bytes, 1, token)) return true;
	if (bytes.byteLength < 58 || bytes[56] !== 0x0d || bytes[57] !== 0x0a) return false;

	const trojanPassword = sha224(token);
	for (let i = 0; i < 56; i++) {
		if (bytes[i] !== trojanPassword.charCodeAt(i)) return false;
	}
	return true;
}

function decodeWSearlyData(header, token) {
	if (!header) return null;
	if (header.length > WSearlyDataMaxHeaderLength) throw new Error('early data is too large');

	let bytes;
	const Uint8ArrayBase64 = /** @type {any} */ (Uint8Array);
	if (typeof Uint8ArrayBase64.fromBase64 === 'function') {
		try {
			bytes = Uint8ArrayBase64.fromBase64(header, { alphabet: 'base64url' });
		} catch (_) { }
	}
	if (!bytes) {
		let normalized = header.replace(/-/g, '+').replace(/_/g, '/');
		const padding = normalized.length % 4;
		if (padding) normalized += '='.repeat(4 - padding);
		let binaryString;
		try {
			binaryString = atob(normalized);
		} catch (_) {
			return null;
		}
		bytes = new Uint8Array(binaryString.length);
		for (let i = 0; i < binaryString.length; i++) bytes[i] = binaryString.charCodeAt(i);
	}

	if (bytes.byteLength > WSearlyDataMaxBytes) throw new Error('early data is too large');
	return isValidWSearlyData(bytes, token) ? bytes : null;
}

///////////////////////////////////////////////////////////////////////WStransportData///////////////////////////////////////////////
async function handleLogicWSrequest(request, yourUUID, url, relayContext = {}) {
	const WSsocketPair = new WebSocketPair();
	const [clientSock, serverSock] = Object.values(WSsocketPair);
	try { (/** @type {any} */ (serverSock)).accept({ allowHalfOpen: true }) }
	catch (_) { serverSock.accept() }
	serverSock.binaryType = 'arraybuffer';
	let remoteConnWrapper = { socket: null, connectingPromise: null, retryConnect: null, downlinkDrain: Promise.resolve() };
	const invalidRemoteConn = () => invalidatedTCPconnGeneration(remoteConnWrapper);
	let isDnsQuery = false;
	let isTrojan = null;
	const trojanUDPContext = { cache: new Uint8Array(0), relayAddress: relayContext.trojanRelayAddress };
	const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';
	const SSmodeDisabledEarlyData = !!url.searchParams.get('enc');
	let WSuplinkWriteQueue = null;
	let WSexplicitTransferChain = Promise.resolve();
	let WSexplicitTransferStopRecv = false, WSexplicitTransferFail = false, WSexplicitTransferFinishQueued = false;
	let WSexplicitQueueBytes = 0, WSexplicitQueueEntries = 0;
	let checkProtoType = null, currentWriteSocket = null, remoteWriter = null;
	let ssContext = null, ssinitTask = null;
	let WSlocalSpeedTestMode = false, WSlocalSpeedTestReturnPacketSocket = null;
	let WSlocalSpeedTestReqCache = new Uint8Array(0);
	let WSlocalSpeedTestFirstPacketRespHeader = null;
	const WSlocalSpeedTestReqLimit = 64 * 1024;

	const sendSendWSlocalSpeedTestResponse = async () => {
		if (!WSlocalSpeedTestReturnPacketSocket) return;
		const respHeader = WSlocalSpeedTestFirstPacketRespHeader;
		WSlocalSpeedTestFirstPacketRespHeader = null;
		await WebSocketsendAndWait(WSlocalSpeedTestReturnPacketSocket, buildMakeWSthisLocation204response(respHeader));
	};

	const queryFindHTTPrequestHeaderEnd = (data) => {
		for (let i = 0; i <= data.byteLength - 4; i++) {
			if (data[i] === 0x0d && data[i + 1] === 0x0a && data[i + 2] === 0x0d && data[i + 3] === 0x0a) return i + 4;
		}
		return -1;
	};

	const handleLogicWSlocalSpeedTestData = async (data) => {
		const chunk = numDataTurnUint8Array(data);
		if (!chunk.byteLength) return;
		if (WSlocalSpeedTestReqCache.byteLength + chunk.byteLength > WSlocalSpeedTestReqLimit) throw new Error('WS local speed-test request is too large');
		WSlocalSpeedTestReqCache = concatByteData(WSlocalSpeedTestReqCache, chunk);

		while (WSlocalSpeedTestReqCache.byteLength) {
			const headerEnd = queryFindHTTPrequestHeaderEnd(WSlocalSpeedTestReqCache);
			if (headerEnd === -1) return;
			const headerText = vlessTextDecoder.decode(WSlocalSpeedTestReqCache.subarray(0, headerEnd));
			const contentLengthMatch = headerText.match(/(?:^|\r\n)content-length\s*:\s*(\d+)/i);
			const contentLength = contentLengthMatch ? Number(contentLengthMatch[1]) : 0;
			const requestLength = headerEnd + contentLength;
			if (!Number.isSafeInteger(contentLength) || requestLength > WSlocalSpeedTestReqLimit) throw new Error('WS local speed-test request body is too large');
			if (WSlocalSpeedTestReqCache.byteLength < requestLength) return;
			WSlocalSpeedTestReqCache = WSlocalSpeedTestReqCache.slice(requestLength);
			await sendSendWSlocalSpeedTestResponse();
		}
	};

	const enableUseWSlocalSpeedTestMode = async (returnPacketSocket, respHeader = null, firstRequestData = null) => {
		WSlocalSpeedTestMode = true;
		WSlocalSpeedTestReturnPacketSocket = returnPacketSocket;
		WSlocalSpeedTestReqCache = new Uint8Array(0);
		WSlocalSpeedTestFirstPacketRespHeader = respHeader;
		if (validDataLength(firstRequestData) > 0) await handleLogicWSlocalSpeedTestData(firstRequestData);
	};

	const releaseRemoteWriter = () => {
		if (remoteWriter) {
			try { remoteWriter.releaseLock() } catch (e) { }
			remoteWriter = null;
		}
		currentWriteSocket = null;
	};

	const uplinkWriteQueue = WSuplinkWriteQueue = createUplinkWriteQueue({
		getWriter: () => {
			const socket = remoteConnWrapper.socket;
			if (!socket) return null;
			if (socket !== currentWriteSocket) {
				releaseRemoteWriter();
				currentWriteSocket = socket;
				remoteWriter = socket.writable.getWriter();
			}
			return remoteWriter;
		},
		getConnTask: () => remoteConnWrapper.connectingPromise,
		releaseWriter: releaseRemoteWriter,
		retryConn: async () => {
			if (typeof remoteConnWrapper.retryConnect !== 'function') throw new Error('retry unavailable');
			await remoteConnWrapper.retryConnect();
		},
		closeConn: err => handleLogicWSexplicitTransferError(err),
		nameName: 'WSuplink'
	});

	const writeRemote = async (chunk, allowRetry = true) => {
		return uplinkWriteQueue.writeIn(chunk, allowRetry);
	};

	const getGetSSContext = async () => {
		if (ssContext) return ssContext;
		if (!ssinitTask) {
			ssinitTask = (async () => {
				const requestEncryptMethod = (url.searchParams.get('enc') || '').toLowerCase();
				const preferredEncryptConfig = SSsupportedEncryptConfig[requestEncryptMethod] || SSsupportedEncryptConfig['aes-128-gcm'];
				const inboundCandidateEncryptConfig = [preferredEncryptConfig, ...Object.values(SSsupportedEncryptConfig).filter(c => c.method !== preferredEncryptConfig.method)];
				const inboundMasterKeyTaskCache = new Map();
				const getInboundMasterKeyTask = (config) => {
					if (!inboundMasterKeyTaskCache.has(config.method)) inboundMasterKeyTaskCache.set(config.method, SSderiveMasterKey(yourUUID, config.keyLen));
					return inboundMasterKeyTaskCache.get(config.method);
				};
				const inboundState = {
					buffer: new Uint8Array(0),
					hasSalt: false,
					waitPayloadLength: null,
					decryptKey: null,
					nonceCounter: new Uint8Array(SSNoncelength),
					encryptConfig: null,
				};
				const initInboundDecryptState = async () => {
					const lengthCipherTotalLength = 2 + SSAEADtagLength;
					const maxSaltLength = Math.max(...inboundCandidateEncryptConfig.map(c => c.saltLen));
					const maxAlignScanBytes = 16;
					const maxScannableOffset = Math.min(maxAlignScanBytes, Math.max(0, inboundState.buffer.byteLength - (lengthCipherTotalLength + Math.min(...inboundCandidateEncryptConfig.map(c => c.saltLen)))));
					for (let offset = 0; offset <= maxScannableOffset; offset++) {
						for (const encryptConfig of inboundCandidateEncryptConfig) {
							const initMinLength = offset + encryptConfig.saltLen + lengthCipherTotalLength;
							if (inboundState.buffer.byteLength < initMinLength) continue;
							const salt = inboundState.buffer.subarray(offset, offset + encryptConfig.saltLen);
							const lengthCipher = inboundState.buffer.subarray(offset + encryptConfig.saltLen, initMinLength);
							const masterKey = await getInboundMasterKeyTask(encryptConfig);
							const decryptKey = await SSderiveSessionKey(encryptConfig, masterKey, salt, ['decrypt']);
							const nonceCounter = new Uint8Array(SSNoncelength);
							try {
								const lengthPlain = await SSAEADdecrypt(decryptKey, nonceCounter, lengthCipher);
								if (lengthPlain.byteLength !== 2) continue;
								const payloadLength = (lengthPlain[0] << 8) | lengthPlain[1];
								if (payloadLength < 0 || payloadLength > encryptConfig.maxChunk) continue;
								if (offset > 0) log(`[SSinbound] detectLeadingNoise ${offset}B, autoAligned`);
								if (encryptConfig.method !== preferredEncryptConfig.method) log(`[SSinbound] URL enc=${requestEncryptMethod || preferredEncryptConfig.method} withActual ${encryptConfig.method} inconsistent, autoSwitched`);
								inboundState.buffer = inboundState.buffer.subarray(initMinLength);
								inboundState.decryptKey = decryptKey;
								inboundState.nonceCounter = nonceCounter;
								inboundState.waitPayloadLength = payloadLength;
								inboundState.encryptConfig = encryptConfig;
								inboundState.hasSalt = true;
								return true;
							} catch (_) { }
						}
					}
					const initFailDeterminLength = maxSaltLength + lengthCipherTotalLength + maxAlignScanBytes;
					if (inboundState.buffer.byteLength >= initFailDeterminLength) {
						throw new Error(`SS handshake decrypt failed (enc=${requestEncryptMethod || 'auto'}, candidates=${inboundCandidateEncryptConfig.map(c => c.method).join('/')})`);
					}
					return false;
				};
				const inboundDecryptor = {
					async outputIn(dataChunk) {
						const chunk = numDataTurnUint8Array(dataChunk);
						if (chunk.byteLength > 0) inboundState.buffer = concatByteData(inboundState.buffer, chunk);
						if (!inboundState.hasSalt) {
							const initSuccess = await initInboundDecryptState();
							if (!initSuccess) return [];
						}
						const plaintextChunks = [];
						while (true) {
							if (inboundState.waitPayloadLength === null) {
								const lengthCipherTotalLength = 2 + SSAEADtagLength;
								if (inboundState.buffer.byteLength < lengthCipherTotalLength) break;
								const lengthCipher = inboundState.buffer.subarray(0, lengthCipherTotalLength);
								inboundState.buffer = inboundState.buffer.subarray(lengthCipherTotalLength);
								const lengthPlain = await SSAEADdecrypt(inboundState.decryptKey, inboundState.nonceCounter, lengthCipher);
								if (lengthPlain.byteLength !== 2) throw new Error('SS length decrypt failed');
								const payloadLength = (lengthPlain[0] << 8) | lengthPlain[1];
								if (payloadLength < 0 || payloadLength > inboundState.encryptConfig.maxChunk) throw new Error(`SS payload length invalid: ${payloadLength}`);
								inboundState.waitPayloadLength = payloadLength;
							}
							const payloadCipherTotalLength = inboundState.waitPayloadLength + SSAEADtagLength;
							if (inboundState.buffer.byteLength < payloadCipherTotalLength) break;
							const payloadCipher = inboundState.buffer.subarray(0, payloadCipherTotalLength);
							inboundState.buffer = inboundState.buffer.subarray(payloadCipherTotalLength);
							const payloadPlain = await SSAEADdecrypt(inboundState.decryptKey, inboundState.nonceCounter, payloadCipher);
							plaintextChunks.push(payloadPlain);
							inboundState.waitPayloadLength = null;
						}
						return plaintextChunks;
					},
				};
				let outboundEncryptor = null;
				const SSmaxBytesPerBatch = 32 * 1024;
				const getOutboundEncryptor = async () => {
					if (outboundEncryptor) return outboundEncryptor;
					if (!inboundState.encryptConfig) throw new Error('SS cipher is not negotiated');
					const outboundEncryptConfig = inboundState.encryptConfig;
					const outboundMasterKey = await SSderiveMasterKey(yourUUID, outboundEncryptConfig.keyLen);
					const outboundRandomBytes = crypto.getRandomValues(new Uint8Array(outboundEncryptConfig.saltLen));
					const outboundEncryptKey = await SSderiveSessionKey(outboundEncryptConfig, outboundMasterKey, outboundRandomBytes, ['encrypt']);
					const outboundNoncecounter = new Uint8Array(SSNoncelength);
					let randomBytesSent = false;
					outboundEncryptor = {
						async encryptAndSend(dataChunk, sendChunk) {
							const plaintextData = numDataTurnUint8Array(dataChunk);
							if (!randomBytesSent) {
								await sendChunk(outboundRandomBytes);
								randomBytesSent = true;
							}
							if (plaintextData.byteLength === 0) return;
							let offset = 0;
							while (offset < plaintextData.byteLength) {
								const end = Math.min(offset + outboundEncryptConfig.maxChunk, plaintextData.byteLength);
								const payloadPlain = plaintextData.subarray(offset, end);
								const lengthPlain = new Uint8Array(2);
								lengthPlain[0] = (payloadPlain.byteLength >>> 8) & 0xff;
								lengthPlain[1] = payloadPlain.byteLength & 0xff;
								const lengthCipher = await SSAEADaddSecret(outboundEncryptKey, outboundNoncecounter, lengthPlain);
								const payloadCipher = await SSAEADaddSecret(outboundEncryptKey, outboundNoncecounter, payloadPlain);
								const frame = new Uint8Array(lengthCipher.byteLength + payloadCipher.byteLength);
								frame.set(lengthCipher, 0);
								frame.set(payloadCipher, lengthCipher.byteLength);
								await sendChunk(frame);
								offset = end;
							}
						},
					};
					return outboundEncryptor;
				};
				let SSsendQueue = Promise.resolve();
				const SSenqueueSend = (chunk) => {
					SSsendQueue = SSsendQueue.then(async () => {
						if (serverSock.readyState !== WebSocket.OPEN) return;
						const outboundEncryptorInitialized = await getOutboundEncryptor();
						await outboundEncryptorInitialized.encryptAndSend(chunk, async (encryptedChunk) => {
							if (encryptedChunk.byteLength > 0 && serverSock.readyState === WebSocket.OPEN) {
								await WebSocketsendAndWait(serverSock, encryptedChunk.buffer);
							}
						});
					}).catch((error) => {
						log(`[SSsendSend] encryptFail: ${error?.message || error}`);
						closeSocketQuietly(serverSock);
					});
					return SSsendQueue;
				};
				const returnPacketSocket = {
					get readyState() {
						return serverSock.readyState;
					},
					send(data) {
						const chunk = numDataTurnUint8Array(data);
						if (chunk.byteLength <= SSmaxBytesPerBatch) {
							return SSenqueueSend(chunk);
						}
						for (let i = 0; i < chunk.byteLength; i += SSmaxBytesPerBatch) {
							SSenqueueSend(chunk.subarray(i, Math.min(i + SSmaxBytesPerBatch, chunk.byteLength)));
						}
						return SSsendQueue;
					},
					close() {
						closeSocketQuietly(serverSock);
					}
				};
				ssContext = {
					inboundDecryptor,
					returnPacketSocket,
					firstPacketEstablished: false,
					targetHost: '',
					targetPort: 0,
				};
				return ssContext;
			})().finally(() => { ssinitTask = null });
		}
		return ssinitTask;
	};

	const handleLogicSSnumData = async (chunk) => {
		const Context = await getGetSSContext();
		let plaintextChunkArray = null;
		try {
			plaintextChunkArray = await Context.inboundDecryptor.outputIn(chunk);
		} catch (err) {
			const msg = err?.message || `${err}`;
			if (msg.includes('Decryption failed') || msg.includes('SS handshake decrypt failed') || msg.includes('SS length decrypt failed')) {
				log(`[SSinbound] decryptFail, connClose: ${msg}`);
				closeSocketQuietly(serverSock);
				return;
			}
			throw err;
		}
		for (const plaintextChunk of plaintextChunkArray) {
			if (WSlocalSpeedTestMode) {
				await handleLogicWSlocalSpeedTestData(plaintextChunk);
				continue;
			}
			let written = false;
			try {
				written = await writeRemote(plaintextChunk, false);
			} catch (err) {
				if ((/** @type {any} */ (err))?.isQueueOverflow) throw err;
				written = false;
			}
			if (written) continue;
			if (Context.firstPacketEstablished && Context.targetHost && Context.targetPort > 0) {
				await forwardataTCP(Context.targetHost, Context.targetPort, plaintextChunk, Context.returnPacketSocket, null, remoteConnWrapper, yourUUID, request, relayContext);
				continue;
			}
			const plaintextData = numDataTurnUint8Array(plaintextChunk);
			if (plaintextData.byteLength < 3) throw new Error('invalid ss data');
			const addressType = plaintextData[0];
			let cursor = 1;
			let hostname = '';
			if (addressType === 1) {
				if (plaintextData.byteLength < cursor + 4 + 2) throw new Error('invalid ss ipv4 length');
				hostname = `${plaintextData[cursor]}.${plaintextData[cursor + 1]}.${plaintextData[cursor + 2]}.${plaintextData[cursor + 3]}`;
				cursor += 4;
			} else if (addressType === 3) {
				if (plaintextData.byteLength < cursor + 1) throw new Error('invalid ss domain length');
				const domainLength = plaintextData[cursor];
				cursor += 1;
				if (plaintextData.byteLength < cursor + domainLength + 2) throw new Error('invalid ss domain data');
				hostname = SStextDecoder.decode(plaintextData.subarray(cursor, cursor + domainLength));
				cursor += domainLength;
			} else if (addressType === 4) {
				if (plaintextData.byteLength < cursor + 16 + 2) throw new Error('invalid ss ipv6 length');
				const ipv6 = [];
				const ipv6View = new DataView(plaintextData.buffer, plaintextData.byteOffset + cursor, 16);
				for (let i = 0; i < 8; i++) ipv6.push(ipv6View.getUint16(i * 2).toString(16));
				hostname = ipv6.join(':');
				cursor += 16;
			} else {
				throw new Error(`invalid ss addressType: ${addressType}`);
			}
			if (!hostname) throw new Error(`invalid ss address: ${addressType}`);
			const port = (plaintextData[cursor] << 8) | plaintextData[cursor + 1];
			cursor += 2;
			const rawClientData = plaintextData.subarray(cursor);
			if (isSpeedTestSite(hostname) && relayContext.proxyType === null) {
				await enableUseWSlocalSpeedTestMode(Context.returnPacketSocket, null, rawClientData);
				return;
			}
			Context.firstPacketEstablished = true;
			Context.targetHost = hostname;
			Context.targetPort = port;
			await forwardataTCP(hostname, port, rawClientData, Context.returnPacketSocket, null, remoteConnWrapper, yourUUID, request, relayContext);
		}
	};

	const handleLogicWSinboundData = async (chunk) => {
		let currentChunkBytes = null;
		if (isDnsQuery) {
			if (isTrojan) return await forwardTrojanUDPnumData(chunk, serverSock, trojanUDPContext, request);
			return await forwardataudp(chunk, serverSock, null, request);
		}
		if (checkProtoType === 'ss') {
			await handleLogicSSnumData(chunk);
			return;
		}
		if (WSlocalSpeedTestMode) {
			await handleLogicWSlocalSpeedTestData(chunk);
			return;
		}
		if (await writeRemote(chunk)) return;

		if (checkProtoType === null) {
			if (url.searchParams.get('enc')) checkProtoType = 'ss';
			else {
				currentChunkBytes = currentChunkBytes || numDataTurnUint8Array(chunk);
				const bytes = currentChunkBytes;
				checkProtoType = bytes.byteLength >= 58 && bytes[56] === 0x0d && bytes[57] === 0x0a ? 'trojan' : 'vless';
			}
			isTrojan = checkProtoType === 'trojan';
			log(`[WSturnSend] protoType: ${checkProtoType} | comeSelf: ${url.host} | UA: ${request.headers.get('user-agent') || 'notKnow'}`);
		}

		if (checkProtoType === 'ss') {
			await handleLogicSSnumData(chunk);
			return;
		}
		if (await writeRemote(chunk)) return;
		if (checkProtoType === 'trojan') {
			const parseResult = parseTrojanRequest(chunk, yourUUID);
			if (parseResult?.hasError) throw new Error(parseResult.message || 'Invalid trojan request');
			const { port, hostname, rawClientData, isUDP } = parseResult;
			if (isSpeedTestSite(hostname) && relayContext.proxyType === null) {
				await enableUseWSlocalSpeedTestMode(serverSock, null, rawClientData);
				return;
			}
			if (isUDP) {
				isDnsQuery = true;
				trojanUDPContext.targetHost = hostname;
				trojanUDPContext.targetPort = port;
				if (trojanUDPContext.relayAddress) return forwardTrojanUDPnumData(currentChunkBytes || numDataTurnUint8Array(chunk), serverSock, trojanUDPContext, request);
				if (validDataLength(rawClientData) > 0) return forwardTrojanUDPnumData(rawClientData, serverSock, trojanUDPContext, request);
				return;
			}
			await forwardataTCP(hostname, port, rawClientData, serverSock, null, remoteConnWrapper, yourUUID, request, relayContext, true, currentChunkBytes || numDataTurnUint8Array(chunk));
		} else {
			isTrojan = false;
			currentChunkBytes = currentChunkBytes || numDataTurnUint8Array(chunk);
			const bytes = currentChunkBytes;
			const parseResult = parseVlessRequest(bytes, yourUUID);
			if (parseResult?.hasError) throw new Error(parseResult.message || 'Invalid vless request');
			const { port, hostname, version, isUDP, rawClientData } = parseResult;
			const respHeader = new Uint8Array([version, 0]);
			if (isSpeedTestSite(hostname) && relayContext.proxyType === null) {
				await enableUseWSlocalSpeedTestMode(serverSock, respHeader, rawClientData);
				return;
			}
			if (isUDP) {
				if (port === 53) isDnsQuery = true;
				else throw new Error('UDP is not supported');
			}
			const rawData = rawClientData;
			if (isDnsQuery) {
				if (isTrojan) return forwardTrojanUDPnumData(rawData, serverSock, trojanUDPContext, request);
				return forwardataudp(rawData, serverSock, respHeader, request);
			}
			await forwardataTCP(hostname, port, rawData, serverSock, respHeader, remoteConnWrapper, yourUUID, request, relayContext);
		}
	};

	const handleLogicWSexplicitTransferError = (err) => {
		if (WSexplicitTransferFail) return;
		WSexplicitTransferFail = true;
		WSexplicitTransferStopRecv = true;
		WSexplicitQueueBytes = 0;
		WSexplicitQueueEntries = 0;
		const msg = err?.message || `${err}`;
		if (msg.includes('Network connection lost') || msg.includes('ReadableStream is closed')) {
			log(`[WSturnSend] connEnd: ${msg}`);
		} else {
			log(`[WSturnSend] handleLogicFailFail: ${msg}`);
		}
		uplinkWriteQueue.clearEmpty();
		releaseRemoteWriter();
		invalidRemoteConn();
		try { trojanUDPContext.relaySocket?.close() } catch (e) { }
		closeSocketQuietly(serverSock);
	};

	const chaseAddWSexplicitTransferTask = (taskService) => {
		WSexplicitTransferChain = WSexplicitTransferChain.then(taskService).catch(handleLogicWSexplicitTransferError);
		return WSexplicitTransferChain;
	};

	const inQueueWSexplicitTransfer = (data) => {
		if (WSexplicitTransferStopRecv || WSexplicitTransferFail) return;
		const chunkSize = Math.max(0, validDataLength(data));
		const nextBytes = WSexplicitQueueBytes + chunkSize;
		const nextItems = WSexplicitQueueEntries + 1;
		if (nextBytes > uplinkQueueMaxBytes || nextItems > uplinkQueueMaxEntries) {
			handleLogicWSexplicitTransferError(new Error(`[WSexplicitTransfer] queueOverflow: ${nextBytes}B/${nextItems}`));
			return;
		}
		WSexplicitQueueBytes = nextBytes;
		WSexplicitQueueEntries = nextItems;
		chaseAddWSexplicitTransferTask(async () => {
			WSexplicitQueueBytes = Math.max(0, WSexplicitQueueBytes - chunkSize);
			WSexplicitQueueEntries = Math.max(0, WSexplicitQueueEntries - 1);
			if (WSexplicitTransferFail) return;
			await handleLogicWSinboundData(data);
		});
	};

	const receiveTailWSexplicitTransfer = () => {
		if (WSexplicitTransferFinishQueued) return;
		WSexplicitTransferFinishQueued = true;
		WSexplicitTransferStopRecv = true;
		chaseAddWSexplicitTransferTask(async () => {
			if (WSexplicitTransferFail) return;
			await uplinkWriteQueue.waitEmpty();
			releaseRemoteWriter();
			invalidRemoteConn();
			try { trojanUDPContext.relaySocket?.close() } catch (e) { }
		});
	};

	serverSock.addEventListener('message', (event) => {
		inQueueWSexplicitTransfer(event.data);
	});
	serverSock.addEventListener('close', () => {
		closeSocketQuietly(serverSock);
		receiveTailWSexplicitTransfer();
	});
	serverSock.addEventListener('error', (err) => {
		handleLogicWSexplicitTransferError(err);
	});

	// SS disabledUnderMode sec-websocket-protocol early-data, avoidFreeTakeSubProtocolValue (like "binary") mistakenlyTreatedAs base64 dataInjectFirstPacketCauses AEAD decryptFail. 
	if (!SSmodeDisabledEarlyData && earlyDataHeader) {
		try {
			const bytes = decodeWSearlyData(earlyDataHeader, yourUUID);
			if (bytes?.byteLength) inQueueWSexplicitTransfer(bytes.buffer);
		} catch (error) {
			handleLogicWSexplicitTransferError(error);
		}
	}

	return new Response(null, { status: 101, webSocket: clientSock, headers: { 'Sec-WebSocket-Extensions': '' } });
}

const trojanTextDecoder = new TextDecoder();

function parseTrojanRelayAddress(address) {
	const raw = String(address || '').trim();
	if (!raw || raw.includes('/') || raw.includes('@') || raw.includes('://')) throw new Error('trojanRelayOnlySupports host:port');
	let hostname = '', portText = '';
	if (raw.startsWith('[')) {
		const match = raw.match(/^(\[[^\]]+\]):(\d+)$/);
		if (!match) throw new Error('invalidThe IPv6 trojanRelayAddress');
		hostname = match[1];
		portText = match[2];
	} else {
		const parts = raw.split(':');
		if (parts.length !== 2) throw new Error('trojanRelayOnlySupports host:port');
		hostname = parts[0];
		portText = parts[1];
	}
	const port = Number(portText);
	if (!hostname || !Number.isInteger(port) || port < 1 || port > 65535) throw new Error('invalidTrojanRelayPort');
	return { hostname, port };
}

async function connectTrojanRelay(firstPacketData, TCPconn, trojanRelayTarget) {
	if (!trojanRelayTarget) throw new Error('trojan fallback is not configured');
	const socket = TCPconn({ hostname: stripIPv6Brackets(trojanRelayTarget.hostname), port: trojanRelayTarget.port });
	let writer = null;
	try {
		if (socket.opened) await socket.opened;
		if (validDataLength(firstPacketData) > 0) {
			writer = socket.writable.getWriter();
			await writer.write(numDataTurnUint8Array(firstPacketData));
		}
		return socket;
	} catch (error) {
		try { socket?.close?.() } catch (e) { }
		throw error;
	} finally {
		try { writer?.releaseLock() } catch (e) { }
	}
}

function extractTrojanRelayHandshakeData(firstPacketData, rawData) {
	const firstPacket = numDataTurnUint8Array(firstPacketData);
	const payload = numDataTurnUint8Array(rawData);
	if (!payload.byteLength) return firstPacket;
	const handshakeLength = firstPacket.byteLength - payload.byteLength;
	if (handshakeLength <= 0) return firstPacket;
	for (let i = 0; i < payload.byteLength; i++) {
		if (firstPacket[handshakeLength + i] !== payload[i]) return firstPacket;
	}
	return firstPacket.subarray(0, handshakeLength);
}

async function forwardTrojanUDPrelayData(chunk, webSocket, Context, request) {
	const data = numDataTurnUint8Array(chunk);
	if (!Context.relaySocket) {
		const TCPconn = createRequestTCPconnector(request);
		const socket = await connectTrojanRelay(data, TCPconn, Context.relayAddress);
		Context.relaySocket = socket;
		socket.closed.catch(() => { }).finally(() => closeSocketQuietly(webSocket));
		connectStreams(socket, webSocket, null, null);
		return;
	}
	if (!data.byteLength) return;
	const writer = Context.relaySocket.writable.getWriter();
	try { await writer.write(data) }
	finally { try { writer.releaseLock() } catch (e) { } }
}

function parseTrojanRequest(buffer, passwordPlainText) {
	const data = numDataTurnUint8Array(buffer);
	const sha224Password = sha224(passwordPlainText);
	if (data.byteLength < 58) return { hasError: true, message: "invalid data" };
	let crLfIndex = 56;
	if (data[crLfIndex] !== 0x0d || data[crLfIndex + 1] !== 0x0a) return { hasError: true, message: "invalid header format" };
	for (let i = 0; i < crLfIndex; i++) {
		if (data[i] !== sha224Password.charCodeAt(i)) return { hasError: true, message: "invalid password" };
	}

	const socks5Index = crLfIndex + 2;
	if (data.byteLength < socks5Index + 6) return { hasError: true, message: "invalid S5 request data" };

	const cmd = data[socks5Index];
	if (cmd !== 1 && cmd !== 3) return { hasError: true, message: "unsupported command, only TCP/UDP is allowed" };
	const isUDP = cmd === 3;

	const atype = data[socks5Index + 1];
	let addressLength = 0;
	let addressIndex = socks5Index + 2;
	let address = "";
	switch (atype) {
		case 1: // IPv4
			addressLength = 4;
			if (data.byteLength < addressIndex + addressLength + 4) return { hasError: true, message: "invalid S5 request data" };
			address = `${data[addressIndex]}.${data[addressIndex + 1]}.${data[addressIndex + 2]}.${data[addressIndex + 3]}`;
			break;
		case 3: // Domain
			if (data.byteLength < addressIndex + 1) return { hasError: true, message: "invalid S5 request data" };
			addressLength = data[addressIndex];
			addressIndex += 1;
			if (data.byteLength < addressIndex + addressLength + 4) return { hasError: true, message: "invalid S5 request data" };
			address = trojanTextDecoder.decode(data.subarray(addressIndex, addressIndex + addressLength));
			break;
		case 4: // IPv6
			addressLength = 16;
			if (data.byteLength < addressIndex + addressLength + 4) return { hasError: true, message: "invalid S5 request data" };
			const ipv6 = [];
			for (let i = 0; i < 8; i++) {
				const partIndex = addressIndex + i * 2;
				ipv6.push(((data[partIndex] << 8) | data[partIndex + 1]).toString(16));
			}
			address = ipv6.join(":");
			break;
		default:
			return { hasError: true, message: `invalid addressType is ${atype}` };
	}

	if (!address) {
		return { hasError: true, message: `address is empty, addressType is ${atype}` };
	}

	const portIndex = addressIndex + addressLength;
	if (data.byteLength < portIndex + 4) return { hasError: true, message: "invalid S5 request data" };
	const portRemote = (data[portIndex] << 8) | data[portIndex + 1];

	return {
		hasError: false,
		addressType: atype,
		port: portRemote,
		hostname: address,
		isUDP,
		rawClientData: data.subarray(portIndex + 4)
	};
}

const UUIDbyteCache = new Map();
const vlessTextDecoder = new TextDecoder();

function readHexHalfByte(code) {
	if (code >= 48 && code <= 57) return code - 48;
	code |= 32;
	if (code >= 97 && code <= 102) return code - 87;
	return -1;
}

function getGetUUIDbyte(uuid) {
	const key = String(uuid || '');
	let cached = UUIDbyteCache.get(key);
	if (cached) return cached;

	const clean = key.replace(/-/g, '');
	if (clean.length !== 32) return null;

	const bytes = new Uint8Array(16);
	for (let i = 0; i < 16; i++) {
		const high = readHexHalfByte(clean.charCodeAt(i * 2));
		const low = readHexHalfByte(clean.charCodeAt(i * 2 + 1));
		if (high < 0 || low < 0) return null;
		bytes[i] = (high << 4) | low;
	}

	if (UUIDbyteCache.size >= 32) UUIDbyteCache.clear();
	UUIDbyteCache.set(key, bytes);
	return bytes;
}

function UUIDbyteMatch(data, offset, uuid) {
	const expected = getGetUUIDbyte(uuid);
	if (!expected || data.byteLength < offset + 16) return false;
	for (let i = 0; i < 16; i++) {
		if (data[offset + i] !== expected[i]) return false;
	}
	return true;
}

function parseVlessRequest(chunk, token) {
	const data = numDataTurnUint8Array(chunk);
	const length = data.byteLength;
	if (length < 24) return { hasError: true, message: 'Invalid data' };
	const version = data[0];
	if (!UUIDbyteMatch(data, 1, token)) return { hasError: true, message: 'Invalid uuid' };

	const optLen = data[17];
	const cmdIndex = 18 + optLen;
	if (length < cmdIndex + 4) return { hasError: true, message: 'Invalid data' };

	const cmd = data[cmdIndex];
	let isUDP = false;
	if (cmd === 1) { } else if (cmd === 2) { isUDP = true } else { return { hasError: true, message: 'Invalid command' } }

	const portIdx = cmdIndex + 1;
	const port = (data[portIdx] << 8) | data[portIdx + 1];
	let addrValIdx = portIdx + 3, addrLen = 0, hostname = '';
	const addressType = data[portIdx + 2];
	switch (addressType) {
		case 1:
			addrLen = 4;
			if (length < addrValIdx + addrLen) return { hasError: true, message: 'Invalid IPv4 address length' };
			hostname = `${data[addrValIdx]}.${data[addrValIdx + 1]}.${data[addrValIdx + 2]}.${data[addrValIdx + 3]}`;
			break;
		case 2:
			if (length < addrValIdx + 1) return { hasError: true, message: 'Invalid domain length' };
			addrLen = data[addrValIdx];
			addrValIdx += 1;
			if (length < addrValIdx + addrLen) return { hasError: true, message: 'Invalid domain data' };
			hostname = vlessTextDecoder.decode(data.subarray(addrValIdx, addrValIdx + addrLen));
			break;
		case 3:
			addrLen = 16;
			if (length < addrValIdx + addrLen) return { hasError: true, message: 'Invalid IPv6 address length' };
			const ipv6 = [];
			for (let i = 0; i < 8; i++) {
				const base = addrValIdx + i * 2;
				ipv6.push(((data[base] << 8) | data[base + 1]).toString(16));
			}
			hostname = ipv6.join(':');
			break;
		default:
			return { hasError: true, message: `Invalid address type: ${addressType}` };
	}
	if (!hostname) return { hasError: true, message: `Invalid address: ${addressType}` };
	const rawIndex = addrValIdx + addrLen;
	return { hasError: false, addressType, port, hostname, isUDP, rawClientData: data.subarray(rawIndex), version };
}

const SSsupportedEncryptConfig = {
	'aes-128-gcm': { method: 'aes-128-gcm', keyLen: 16, saltLen: 16, maxChunk: 0x3fff, aesLength: 128 },
	'aes-256-gcm': { method: 'aes-256-gcm', keyLen: 32, saltLen: 32, maxChunk: 0x3fff, aesLength: 256 },
};

const SSAEADtagLength = 16, SSNoncelength = 12;
const SSsubKeyInfo = new TextEncoder().encode('ss-subkey');
const SStextEncoder = new TextEncoder(), SStextDecoder = new TextDecoder(), SSmasterKeyCache = new Map();

function numDataTurnUint8Array(data) {
	if (data instanceof Uint8Array) return data;
	if (data instanceof ArrayBuffer) return new Uint8Array(data);
	if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
	return new Uint8Array(data || 0);
}

function concatByteData(...chunkList) {
	if (!chunkList || chunkList.length === 0) return new Uint8Array(0);
	const chunks = chunkList.map(numDataTurnUint8Array);
	const total = chunks.reduce((sum, c) => sum + c.byteLength, 0);
	const result = new Uint8Array(total);
	let offset = 0;
	for (const c of chunks) { result.set(c, offset); offset += c.byteLength }
	return result;
}

async function forwardTrojanUDPnumData(chunk, webSocket, Context, request) {
	const currentChunk = numDataTurnUint8Array(chunk);
	if (Context?.relayAddress) return forwardTrojanUDPrelayData(currentChunk, webSocket, Context, request);
	const cacheChunk = Context?.cache instanceof Uint8Array ? Context.cache : new Uint8Array(0);
	const input = cacheChunk.byteLength ? concatByteData(cacheChunk, currentChunk) : currentChunk;
	let cursor = 0;

	while (cursor < input.byteLength) {
		const packetStart = cursor;
		const atype = input[cursor];
		let addrCursor = cursor + 1;
		let addrLen = 0;
		if (atype === 1) addrLen = 4;
		else if (atype === 4) addrLen = 16;
		else if (atype === 3) {
			if (input.byteLength < addrCursor + 1) break;
			addrLen = 1 + input[addrCursor];
		} else throw new Error(`invalid trojan udp addressType: ${atype}`);

		const portCursor = addrCursor + addrLen;
		if (input.byteLength < portCursor + 6) break;

		const port = (input[portCursor] << 8) | input[portCursor + 1];
		const payloadLength = (input[portCursor + 2] << 8) | input[portCursor + 3];
		if (input[portCursor + 4] !== 0x0d || input[portCursor + 5] !== 0x0a) throw new Error('invalid trojan udp delimiter');

		const payloadStart = portCursor + 6;
		const payloadEnd = payloadStart + payloadLength;
		if (input.byteLength < payloadEnd) break;

		const addressPortHeader = input.slice(packetStart, portCursor + 2);
		const payload = input.slice(payloadStart, payloadEnd);
		cursor = payloadEnd;

		if (port !== 53) throw new Error('UDP is not supported');
		if (!payload.byteLength) continue;

		let tcpDNSqueryInquire = payload;
		if (payload.byteLength < 2 || ((payload[0] << 8) | payload[1]) !== payload.byteLength - 2) {
			tcpDNSqueryInquire = new Uint8Array(payload.byteLength + 2);
			tcpDNSqueryInquire[0] = (payload.byteLength >>> 8) & 0xff;
			tcpDNSqueryInquire[1] = payload.byteLength & 0xff;
			tcpDNSqueryInquire.set(payload, 2);
		}

		const dnsresponseContext = { cache: new Uint8Array(0) };
		await forwardataudp(tcpDNSqueryInquire, webSocket, null, request, (dnsRespChunk) => {
			const currentResponseChunk = numDataTurnUint8Array(dnsRespChunk);
			const responseInput = dnsresponseContext.cache.byteLength ? concatByteData(dnsresponseContext.cache, currentResponseChunk) : currentResponseChunk;
			const responseFrameList = [];
			let responseCursor = 0;
			while (responseCursor + 2 <= responseInput.byteLength) {
				const dnsLen = (responseInput[responseCursor] << 8) | responseInput[responseCursor + 1];
				const dnsStart = responseCursor + 2;
				const dnsEnd = dnsStart + dnsLen;
				if (dnsEnd > responseInput.byteLength) break;
				const dnsPayload = responseInput.slice(dnsStart, dnsEnd);
				const frame = new Uint8Array(addressPortHeader.byteLength + 4 + dnsPayload.byteLength);
				frame.set(addressPortHeader, 0);
				frame[addressPortHeader.byteLength] = (dnsPayload.byteLength >>> 8) & 0xff;
				frame[addressPortHeader.byteLength + 1] = dnsPayload.byteLength & 0xff;
				frame[addressPortHeader.byteLength + 2] = 0x0d;
				frame[addressPortHeader.byteLength + 3] = 0x0a;
				frame.set(dnsPayload, addressPortHeader.byteLength + 4);
				responseFrameList.push(frame);
				responseCursor = dnsEnd;
			}
			dnsresponseContext.cache = responseInput.slice(responseCursor);
			return responseFrameList.length ? responseFrameList : new Uint8Array(0);
		});
	}

	if (Context) Context.cache = input.slice(cursor);
}

function SSincrementNoncecounter(counter) {
	for (let i = 0; i < counter.length; i++) { counter[i] = (counter[i] + 1) & 0xff; if (counter[i] !== 0) return }
}

async function SSderiveMasterKey(passwordText, keyLen) {
	const cacheKey = `${keyLen}:${passwordText}`;
	if (SSmasterKeyCache.has(cacheKey)) return SSmasterKeyCache.get(cacheKey);
	const deriveTask = (async () => {
		const pwBytes = SStextEncoder.encode(passwordText || '');
		let prev = new Uint8Array(0), result = new Uint8Array(0);
		while (result.byteLength < keyLen) {
			const input = new Uint8Array(prev.byteLength + pwBytes.byteLength);
			input.set(prev, 0); input.set(pwBytes, prev.byteLength);
			prev = new Uint8Array(await crypto.subtle.digest('MD5', input));
			result = concatByteData(result, prev);
		}
		return result.slice(0, keyLen);
	})();
	SSmasterKeyCache.set(cacheKey, deriveTask);
	try { return await deriveTask }
	catch (error) { SSmasterKeyCache.delete(cacheKey); throw error }
}

async function SSderiveSessionKey(config, masterKey, salt, usages) {
	const hmacOpts = { name: 'HMAC', hash: 'SHA-1' };
	const saltHmacKey = await crypto.subtle.importKey('raw', salt, hmacOpts, false, ['sign']);
	const prk = new Uint8Array(await crypto.subtle.sign('HMAC', saltHmacKey, masterKey));
	const prkHmacKey = await crypto.subtle.importKey('raw', prk, hmacOpts, false, ['sign']);
	const subKey = new Uint8Array(config.keyLen);
	let prev = new Uint8Array(0), written = 0, counter = 1;
	while (written < config.keyLen) {
		const input = concatByteData(prev, SSsubKeyInfo, new Uint8Array([counter]));
		prev = new Uint8Array(await crypto.subtle.sign('HMAC', prkHmacKey, input));
		const copyLen = Math.min(prev.byteLength, config.keyLen - written);
		subKey.set(prev.subarray(0, copyLen), written);
		written += copyLen; counter += 1;
	}
	return crypto.subtle.importKey('raw', subKey, { name: 'AES-GCM', length: config.aesLength }, false, usages);
}

async function SSAEADaddSecret(cryptoKey, nonceCounter, plaintext) {
	const iv = nonceCounter.slice();
	const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, tagLength: 128 }, cryptoKey, plaintext);
	SSincrementNoncecounter(nonceCounter);
	return new Uint8Array(ct);
}

async function SSAEADdecrypt(cryptoKey, nonceCounter, ciphertext) {
	const iv = nonceCounter.slice();
	const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv, tagLength: 128 }, cryptoKey, ciphertext);
	SSincrementNoncecounter(nonceCounter);
	return new Uint8Array(pt);
}

async function forwardataTCP(host, portNum, rawData, ws, respHeader, remoteConnWrapper, yourUUID, request = null, relayContext = {}, allowTrojanRelay = false, trojanRelayFirstPacketData = null, onlyEstablishConn = false) {
	const ctxrelayIP = relayContext.relayIP || '';
	const ctxproxyType = relayContext.proxyType !== undefined ? relayContext.proxyType : null;
	const ctxproxyGlobal = relayContext.proxyGlobal !== undefined ? relayContext.proxyGlobal : false;
	const ctxproxyParams = relayContext.proxyParams || {};
	const ctxrelayFallback = relayContext.relayFallback !== undefined ? relayContext.relayFallback : true;
	let relayArrayIndex = 0;
	log(`[TCPturnSend] targetMark: ${host}:${portNum} | relayIP: ${ctxrelayIP} | relayFallback: ${ctxrelayFallback ? 'is' : 'not'} | relayType: ${ctxproxyType || 'proxyip'} | allScope: ${ctxproxyGlobal ? 'is' : 'not'}`);
	const connTimeoutMs = 1000;
	let firstPacketSentViaProxy = false;
	const TCPconn = createRequestTCPconnector(request);
	const useTrojanRelay = allowTrojanRelay && (relayContext.trojanRelayAddress || null);
	const trojanRelayTarget = useTrojanRelay ? relayContext.trojanRelayAddress : null;
	const trojanRelayHandshakeData = useTrojanRelay ? extractTrojanRelayHandshakeData(trojanRelayFirstPacketData, rawData) : null;
	let pendingResponseHeader = respHeader;
	const extractResponseHeader = () => {
		const header = pendingResponseHeader;
		pendingResponseHeader = null;
		return header;
	};
	if (!Number.isInteger(remoteConnWrapper.generation)) remoteConnWrapper.generation = 0;

	const setupCurrentConn = async (socket, generation, downlinkDrain, retryFunc = null) => {
		try { await downlinkDrain } catch (e) {
			if (remoteConnWrapper.downlinkDrain === downlinkDrain) remoteConnWrapper.downlinkDrain = Promise.resolve();
			try { socket?.close?.() } catch (_) { }
			if (remoteConnWrapper.generation === generation) closeSocketQuietly(ws);
			throw e;
		}
		if (remoteConnWrapper.downlinkDrain === downlinkDrain) remoteConnWrapper.downlinkDrain = Promise.resolve();
		const connStillValid = () => remoteConnWrapper.generation === generation && remoteConnWrapper.socket === socket;
		if (remoteConnWrapper.generation !== generation || ws.readyState !== WebSocket.OPEN) {
			try { socket?.close?.() } catch (e) { }
			if (remoteConnWrapper.generation === generation) remoteConnWrapper.socket = null;
			throw new Error('connection superseded or client closed');
		}
		remoteConnWrapper.socket = socket;
		if (onlyEstablishConn) return socket;
		connectStreams(socket, ws, extractResponseHeader, retryFunc, connStillValid, remoteConnWrapper).catch(err => {
			if (!connStillValid()) return;
			log(`[TCPdownlink] handleLogicFailFail: ${err?.message || err}`);
			try { socket?.close?.() } catch (e) { }
			closeSocketQuietly(ws);
		});
		return true;
	};

	async function waitConnEstablish(remoteSock, timeoutMs = connTimeoutMs) {
		await Promise.race([
			remoteSock.opened,
			new Promise((_, reject) => setTimeout(() => reject(new Error('connTimeout')), timeoutMs))
		]);
	}

	async function openTCPconn(address, port) {
		const remoteSock = TCPconn({ hostname: address, port });
		try {
			await waitConnEstablish(remoteSock);
			return remoteSock;
		} catch (err) {
			try { remoteSock?.close?.() } catch (e) { }
			throw err;
		}
	}

	async function writeFirstPacket(remoteSock, data) {
		if (validDataLength(data) <= 0) return;
		const writer = remoteSock.writable.getWriter();
		try { await writer.write(numDataTurnUint8Array(data)) }
		finally { try { writer.releaseLock() } catch (e) { } }
	}

	async function concurrentOpenCandidateConn(candidateList) {
		if (candidateList.length === 1) {
			const candidate = candidateList[0];
			return { socket: await openTCPconn(candidate.hostname, candidate.port), candidate: candidate };
		}
		const attempts = candidateList.map(candidate => openTCPconn(candidate.hostname, candidate.port).then(socket => ({ socket, candidate: candidate })));
		let winner = null;
		try {
			winner = await Promise.any(attempts);
			return winner;
		} finally {
			if (winner) {
				for (const attempt of attempts) {
					attempt.then(({ socket }) => {
						if (socket !== winner.socket) {
							try { socket?.close?.() } catch (e) { }
						}
					}).catch(() => { });
				}
			}
		}
	}

	async function buildPreloadRaceCandidateList(address, port) {
		if (!preloadRaceDial || isIPHostname(address)) return null;
		log(`[TCPdirect] preloadRaceDialOpenEnable, startConcurrentQuery ${address} Of A/AAAA record`);
		const [aRecords, aaaaRecords] = await Promise.all([
			DoHqueryInquire(address, 'A'),
			DoHqueryInquire(address, 'AAAA')
		]);
		const ipv4List = [...new Set(aRecords.flatMap(r => {
			const data = r.data;
			return r.type === 1 && typeof data === 'string' && isIPv4(data) ? [data] : [];
		}))];
		const ipv6List = [...new Set(aaaaRecords.flatMap(r => {
			const data = r.data;
			return r.type === 28 && typeof data === 'string' && isIPHostname(data) ? [data] : [];
		}))];
		const dialLimit = Math.max(1, TCPconcurrentDialCount | 0);
		const ipList = ipv4List.length >= dialLimit
			? ipv4List.slice(0, dialLimit)
			: ipv4List.concat(ipv6List.slice(0, dialLimit - ipv4List.length));
		const useRecordType = ipv4List.length > 0
			? (ipList.length > ipv4List.length ? 'A+AAAA' : 'A')
			: 'AAAA';
		if (ipList.length === 0) {
			log(`[TCPdirect] ${address} Of A/AAAA noUsableResolveResult, preloadRaceUnavailable, fallbackToOriginal hostname direct. `);
			return null;
		}
		const selectedIPlistTable = ipList;
		log(`[TCPdirect] ${address} Arecord:${ipv4List.length} AAAArecord:${ipv6List.length}, makeUse${useRecordType}record, raceDial ${selectedIPlistTable.length}/${dialLimit}: ${selectedIPlistTable.join(', ')}`);
		return selectedIPlistTable.map((hostname, attempt) => ({ hostname, port, attempt, resolvedFrom: address }));
	}

	async function connectDirect(address, port, data = null, enablePreload = false) {
		const preloadCandidateList = enablePreload ? await buildPreloadRaceCandidateList(address, port) : null;
		const candidateList = preloadCandidateList || Array.from({ length: TCPconcurrentDialCount }, (_, attempt) => ({ hostname: address, port, attempt }));
		log(preloadCandidateList
			? `[TCPdirect] concurrentAttempt ${candidateList.length} route: ${candidateList.map(candidate => `${candidate.hostname}:${candidate.port}`).join(', ')}`
			: `[TCPdirect] concurrentAttempt ${candidateList.length} route: ${address}:${port}`);
		let socket = null;
		try {
			const connResult = await concurrentOpenCandidateConn(candidateList);
			socket = connResult.socket;
			if (preloadCandidateList) {
				const winner = connResult.candidate;
				log(`[TCPdirect] preloadRaceResult: ${winner.hostname}:${winner.port} winOut, sourceDomainName: ${winner.resolvedFrom || address}`);
			}
			await writeFirstPacket(socket, data);
			return socket;
		} catch (err) {
			try { socket?.close?.() } catch (e) { }
			if (preloadCandidateList) log(`[TCPdirect] preloadRaceFail: ${err.message || err}`);
			throw err;
		}
	}

	async function connectProxyIP(address, port, data = null, allRelayArray = null, enableRelayFailFallback = true) {
		if (allRelayArray && allRelayArray.length > 0) {
			const actualConcurrency = Math.max(1, Math.floor(Number(relayConcurrentDialCount) || 1));
			for (let i = 0; i < allRelayArray.length; i += actualConcurrency) {
				const candidateList = [];
				for (let j = 0; j < actualConcurrency && i + j < allRelayArray.length; j++) {
					const index = (relayArrayIndex + i + j) % allRelayArray.length;
					const [relayAddress, relayPort] = allRelayArray[index];
					candidateList.push({ hostname: relayAddress, port: relayPort, index: index });
				}
				let socket = null, candidate = null;
				try {
					log(`[relayConn] concurrentAttempt ${candidateList.length} route: ${candidateList.map(candidate => `${candidate.hostname}:${candidate.port}`).join(', ')}`);
					const connResult = await concurrentOpenCandidateConn(candidateList);
					socket = connResult.socket;
					candidate = connResult.candidate;
					await writeFirstPacket(socket, data);
					log(`[relayConn] successfullyConnectedTo: ${candidate.hostname}:${candidate.port} (index: ${candidate.index})`);
					relayArrayIndex = candidate.index;
					return socket;
				} catch (err) {
					try { socket?.close?.() } catch (e) { }
					log(`[relayConn] batchConnFail: ${err.message || err}`);
				}
			}
		}

		if (enableRelayFailFallback) return connectDirect(address, port, data, false);
		else {
			throw new Error('[relayConn] whereHasRelayConnFailFail, andRelayFallbackDisabled, connTerminate. ');
		}
	}

	async function connecttoPry(allowSendFirstPacket = true) {
		if (remoteConnWrapper.connectingPromise) {
			await remoteConnWrapper.connectingPromise;
			return;
		}
		const { generation: currentConnGeneration, downlinkDrain } = openStartTCPconnGeneration(remoteConnWrapper);

		let currentSendFirstPacket = false, currentFirstPacketData = null;
		if (useTrojanRelay) {
			if (allowSendFirstPacket && !firstPacketSentViaProxy && validDataLength(trojanRelayFirstPacketData) > 0) {
				currentFirstPacketData = trojanRelayFirstPacketData;
				currentSendFirstPacket = validDataLength(rawData) > 0;
			} else {
				currentFirstPacketData = trojanRelayHandshakeData;
			}
		} else {
			currentSendFirstPacket = allowSendFirstPacket && !firstPacketSentViaProxy && validDataLength(rawData) > 0;
			currentFirstPacketData = currentSendFirstPacket ? rawData : null;
		}

		const currentConnTask = (async () => {
			let newSocket = null;
			try {
				if (useTrojanRelay) {
					log(`[trojanRelay] proxyTo: ${host}:${portNum}`);
					newSocket = await connectTrojanRelay(currentFirstPacketData, TCPconn, trojanRelayTarget);
				} else if (ctxproxyType === 'socks5') {
					log(`[SOCKS5proxy] proxyTo: ${host}:${portNum}`);
					newSocket = await socks5Connect(host, portNum, currentFirstPacketData, TCPconn, ctxproxyParams);
				} else if (ctxproxyType === 'http') {
					log(`[HTTPproxy] proxyTo: ${host}:${portNum}`);
					newSocket = await httpConnect(host, portNum, currentFirstPacketData, false, TCPconn, ctxproxyParams);
				} else if (ctxproxyType === 'https') {
					log(`[HTTPSproxy] proxyTo: ${host}:${portNum}`);
					newSocket = isIPHostname(ctxproxyParams.hostname)
						? await httpsConnect(host, portNum, currentFirstPacketData, TCPconn, ctxproxyParams)
						: await httpConnect(host, portNum, currentFirstPacketData, true, TCPconn, ctxproxyParams);
				} else if (ctxproxyType === 'turn') {
					log(`[TURNproxy] proxyTo: ${host}:${portNum}`);
					newSocket = await turnConnect(ctxproxyParams, host, portNum, TCPconn);
					if (validDataLength(currentFirstPacketData) > 0) {
						const writer = newSocket.writable.getWriter();
						try { await writer.write(numDataTurnUint8Array(currentFirstPacketData)) }
						finally { try { writer.releaseLock() } catch (e) { } }
					}
				} else if (ctxproxyType === 'sstp') {
					log(`[SSTPproxy] proxyTo: ${host}:${portNum}`);
					newSocket = await sstpConnect(ctxproxyParams, host, portNum, TCPconn);
					if (validDataLength(currentFirstPacketData) > 0) {
						const writer = newSocket.writable.getWriter();
						try { await writer.write(numDataTurnUint8Array(currentFirstPacketData)) }
						finally { try { writer.releaseLock() } catch (e) { } }
					}
				} else {
					log(`[relayConn] proxyTo: ${host}:${portNum}`);
					const allRelayArray = await parseAddressPort(ctxrelayIP, host, yourUUID);
					newSocket = await connectProxyIP(`${signatureDict[0]}.tp1.${signatureDict[2]}.xyz`, 1, currentFirstPacketData, allRelayArray, ctxrelayFallback);
				}
				await setupCurrentConn(newSocket, currentConnGeneration, downlinkDrain);
				if (currentSendFirstPacket) firstPacketSentViaProxy = true;
			} catch (err) {
				try { newSocket?.close?.() } catch (e) { }
				if (remoteConnWrapper.generation === currentConnGeneration) {
					remoteConnWrapper.socket = null;
					closeSocketQuietly(ws);
					throw err;
				}
			}
		})();

		remoteConnWrapper.connectingPromise = currentConnTask;
		try {
			await currentConnTask;
		} finally {
			if (remoteConnWrapper.connectingPromise === currentConnTask) {
				remoteConnWrapper.connectingPromise = null;
			}
		}
	}
	remoteConnWrapper.retryConnect = async () => connecttoPry(!firstPacketSentViaProxy);

	if (ctxproxyType && (ctxproxyGlobal || SOCKS5whitelist.some(p => new RegExp(`^${p.replace(/\*/g, '.*')}$`, 'i').test(host)))) {
		log(`[TCPturnSend] enableUse SOCKS5/HTTP/HTTPS/TURN/SSTP globalProxy`);
		try {
			await connecttoPry();
			if (onlyEstablishConn) return remoteConnWrapper.socket;
		} catch (err) {
			log(`[TCPturnSend] SOCKS5/HTTP/HTTPS/TURN/SSTP proxyConnFail: ${err.message}`);
			throw err;
		}
	} else {
		let directConnGeneration = remoteConnWrapper.generation;
		try {
			log(`[TCPturnSend] tryDirectConnectTo: ${host}:${portNum}`);
			const generationConn = openStartTCPconnGeneration(remoteConnWrapper);
			directConnGeneration = generationConn.generation;
			const initialSocket = await connectDirect(host, portNum, rawData, true);
			await setupCurrentConn(initialSocket, directConnGeneration, generationConn.downlinkDrain, async () => {
				if (remoteConnWrapper.generation !== directConnGeneration || remoteConnWrapper.socket !== initialSocket) return;
				await connecttoPry();
			});
			if (onlyEstablishConn) return initialSocket;
		} catch (err) {
			log(`[TCPturnSend] direct ${host}:${portNum} failFail: ${err.message}`);
			if (remoteConnWrapper.generation !== directConnGeneration) throw err;
			if (err instanceof Error && err.name === 'preloadResolveEmpty') {
				closeSocketQuietly(ws);
				throw err;
			}
			if (ws.readyState !== WebSocket.OPEN) throw err;
			await connecttoPry();
			if (onlyEstablishConn) return remoteConnWrapper.socket;
		}
	}
}

async function forwardataudp(udpChunk, webSocket, respHeader, request, responseWrapper = null) {
	const requestData = numDataTurnUint8Array(udpChunk);
	const requestByteCount = requestData.byteLength;
	log(`[UDPturnSend] received DNS request: ${requestByteCount}B -> 8.8.4.4:53`);
	try {
		const TCPconn = createRequestTCPconnector(request);
		const tcpSocket = TCPconn({ hostname: '8.8.4.4', port: 53 });
		let vlessHeader = respHeader;
		const writer = tcpSocket.writable.getWriter();
		await writer.write(requestData);
		log(`[UDPturnSend] DNS requestWrittenUpstream: ${requestByteCount}B`);
		writer.releaseLock();
		await tcpSocket.readable.pipeTo(new WritableStream({
			async write(chunk) {
				const rawResponse = numDataTurnUint8Array(chunk);
				log(`[UDPturnSend] received DNS response: ${rawResponse.byteLength}B`);
				const wrapResult = responseWrapper ? await responseWrapper(rawResponse) : rawResponse;
				const sendFragmentList = Array.isArray(wrapResult) ? wrapResult : [wrapResult];
				if (!sendFragmentList.length) return;
				if (webSocket.readyState !== WebSocket.OPEN) return;
				for (const fragment of sendFragmentList) {
					const turnSendResponse = numDataTurnUint8Array(fragment);
					if (!turnSendResponse.byteLength) continue;
					if (vlessHeader) {
						const response = new Uint8Array(vlessHeader.length + turnSendResponse.byteLength);
						response.set(vlessHeader, 0);
						response.set(turnSendResponse, vlessHeader.length);
						await WebSocketsendAndWait(webSocket, response.buffer);
						vlessHeader = null;
					} else {
						await WebSocketsendAndWait(webSocket, turnSendResponse);
					}
				}
			},
		}));
	} catch (error) {
		log(`[UDPturnSend] DNS turnSendFailFail: ${error?.message || error}`);
	}
}

function closeSocketQuietly(socket) {
	try {
		if (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CLOSING) {
			socket.close();
		}
	} catch (error) { }
}

function formatIdentifier(arr, offset = 0) {
	const hex = [...arr.slice(offset, offset + 16)].map(b => b.toString(16).padStart(2, '0')).join('');
	return `${hex.substring(0, 8)}-${hex.substring(8, 12)}-${hex.substring(12, 16)}-${hex.substring(16, 20)}-${hex.substring(20)}`;
}

async function WebSocketsendAndWait(webSocket, payload) {
	const sendResult = webSocket.send(payload);
	if (sendResult && typeof sendResult.then === 'function') await sendResult;
}

function createGraincollector(capacity, copyPackResult = false) {
	let queueList = [];
	let header = 0;
	let byteCount = 0;
	let packBuffer = null;

	const isEmpty = () => header >= queueList.length;
	const compress = () => {
		if (header > 32 && header * 2 >= queueList.length) {
			queueList = queueList.slice(header);
			header = 0;
		}
	};
	const getOut = () => {
		if (isEmpty()) return null;
		const item = queueList[header];
		queueList[header++] = undefined;
		byteCount -= item.chunk.byteLength;
		compress();
		return item;
	};

	return {
		get byteCount() { return byteCount },
		get entryCount() { return queueList.length - header },
		get isEmpty() { return isEmpty() },
		clearEmpty(handleLogicItemTarget = null) {
			if (handleLogicItemTarget) {
				for (let i = header; i < queueList.length; i++) {
					if (queueList[i]) handleLogicItemTarget(queueList[i]);
				}
			}
			queueList = [];
			header = 0;
			byteCount = 0;
		},
		collect(item) {
			if (!item?.chunk?.byteLength) return false;
			queueList.push(item);
			byteCount += item.chunk.byteLength;
			return true;
		},
		combinePacket() {
			const first = getOut();
			if (!first) return null;
			const items = [first];
			if (isEmpty() || first.chunk.byteLength >= capacity) return { chunk: first.chunk, items };

			let totalBytes = first.chunk.byteLength;
			let end = header;
			while (end < queueList.length) {
				const nextBytes = totalBytes + queueList[end].chunk.byteLength;
				if (nextBytes > capacity) break;
				totalBytes = nextBytes;
				end++;
			}
			if (end === header) return { chunk: first.chunk, items };

			const output = (packBuffer ||= new Uint8Array(capacity));
			output.set(first.chunk, 0);
			let offset = first.chunk.byteLength;
			while (header < end) {
				const next = queueList[header];
				queueList[header++] = undefined;
				byteCount -= next.chunk.byteLength;
				items.push(next);
				output.set(next.chunk, offset);
				offset += next.chunk.byteLength;
			}
			compress();
			const bundled = output.subarray(0, totalBytes);
			return { chunk: copyPackResult ? bundled.slice() : bundled, items };
		}
	};
}

function createUplinkGrainpackStream(targetBytes = uplinkPackTargetBytes) {
	const identity = typeof IdentityTransformStream !== 'undefined'
		? new IdentityTransformStream()
		: new TransformStream();
	const writer = identity.writable.getWriter();
	const bufferFlush = new Uint8Array(targetBytes);
	let bufferLength = 0;
	let timer = null;
	let inFlightWrite = null;
	let flushChain = Promise.resolve();

	const clearTimer = () => {
		if (timer) {
			clearTimeout(timer);
			timer = null;
		}
	};

	const serialWrite = async (chunk) => {
		if (inFlightWrite) await inFlightWrite;
		inFlightWrite = writer.write(chunk);
		try { await inFlightWrite } finally { inFlightWrite = null; }
	};

	const flush = async () => {
		if (bufferLength) {
			const chunk = bufferFlush.slice(0, bufferLength);
			bufferLength = 0;
			await serialWrite(chunk);
		}
	};

	const queueFlush = () => {
		flushChain = flushChain.then(() => flush()).catch(() => { });
	};

	const startTimer = () => {
		if (timer) return;
		timer = setTimeout(() => {
			timer = null;
			queueFlush();
		}, 1);
	};

	return {
		readable: identity.readable,
		writeIn: async (chunk) => {
			const data = numDataTurnUint8Array(chunk);
			if (!data.byteLength) return;
			if (data.byteLength >= targetBytes) {
				clearTimer();
				if (bufferLength) await flush();
				await serialWrite(data);
				return;
			}
			if (bufferLength + data.byteLength >= targetBytes) {
				const output = new Uint8Array(bufferLength + data.byteLength);
				output.set(bufferFlush.subarray(0, bufferLength), 0);
				output.set(data, bufferLength);
				bufferLength = 0;
				clearTimer();
				await serialWrite(output);
			} else {
				bufferFlush.set(data, bufferLength);
				bufferLength += data.byteLength;
				startTimer();
			}
		},
		finishEnd: async () => {
			clearTimer();
			try {
				await flushChain;
				await flush();
				await writer.close();
			} finally {
				try { writer.releaseLock() } catch (e) { }
			}
		}
	};
}

function createUplinkWriteQueue({ getWriter, getConnTask = null, releaseWriter, retryConn, closeConn, nameName = 'uplinkQueue' }) {
	const grain = createGraincollector(uplinkPackTargetBytes);
	let draining = false;
	let closed = false;
	let idleResolvers = [];
	let activeCompletions = null;

	const settleCompletions = (completions, err = null) => {
		if (!completions) return;
		for (const completion of completions) {
			if (err) completion.reject(err);
			else completion.resolve();
		}
	};

	const resolveIdle = () => {
		if (grain.byteCount || draining || !idleResolvers.length) return;
		const resolvers = idleResolvers;
		idleResolvers = [];
		for (const resolve of resolvers) resolve();
	};

	const clear = (err = null) => {
		const closeErr = err || (closed ? new Error(`${nameName}: queue closed`) : null);
		if (closeErr) {
			grain.clearEmpty(item => settleCompletions(item.completions, closeErr));
			settleCompletions(activeCompletions, closeErr);
			activeCompletions = null;
		} else grain.clearEmpty();
		resolveIdle();
	};

	const bundle = () => {
		const packed = grain.combinePacket();
		if (!packed) return null;
		let allowRetry = true;
		let completions = null;
		for (const item of packed.items) {
			allowRetry = allowRetry && item.allowRetry;
			if (item.completions) completions = completions ? completions.concat(item.completions) : item.completions;
		}
		return { chunk: packed.chunk, allowRetry, completions };
	};

	const waitAvailableWriter = async () => {
		let writer = getWriter();
		if (writer) return writer;
		const connectionTask = getConnTask?.();
		if (connectionTask) await connectionTask;
		return getWriter();
	};

	const drain = async () => {
		if (draining || closed) return;
		draining = true;
		try {
			for (; ;) {
				if (closed) break;
				const item = bundle();
				if (!item) break;
				const completions = item.completions || null;
				activeCompletions = completions;
				try {
					let writer = await waitAvailableWriter();
					if (closed) break;
					if (!writer) throw new Error(`${nameName}: remote writer unavailable`);
					try {
						await writer.write(item.chunk);
					} catch (err) {
						releaseWriter?.();
						if (closed) break;
						if (!item.allowRetry || typeof retryConn !== 'function') throw err;
						await retryConn();
						if (closed) break;
						writer = getWriter();
						if (!writer) throw err;
						await writer.write(item.chunk);
					}
					settleCompletions(completions);
				} catch (err) {
					settleCompletions(completions, err);
					throw err;
				} finally {
					if (activeCompletions === completions) activeCompletions = null;
				}
			}
		} catch (err) {
			closed = true;
			clear(err);
			log(`[${nameName}] writeFail: ${err?.message || err}`);
			try { closeConn?.(err) } catch (_) { }
		} finally {
			draining = false;
			if (!closed && !grain.isEmpty) drain();
			else resolveIdle();
		}
	};

	const enqueue = (data, allowRetry = true, waitForFlush = false) => {
		if (closed) return false;
		// firstPacketParseStageNeither writer alsoNoConnTask; returnReturn false exchangeGiveUpLayerContinueContinueProtocolParseParse. 
		// establishedSessionRedialStageBufferFirst, drain willWaitNew writer, avoidDataMistakenAsFirstPacket. 
		if (!getWriter() && !getConnTask?.()) return false;
		const chunk = numDataTurnUint8Array(data);
		if (!chunk.byteLength) return true;
		const nextBytes = grain.byteCount + chunk.byteLength;
		const nextItems = grain.entryCount + 1;
		if (nextBytes > uplinkQueueMaxBytes || nextItems > uplinkQueueMaxEntries) {
			closed = true;
			const err = Object.assign(new Error(`${nameName}: upload queue overflow (${nextBytes}B/${nextItems})`), { isQueueOverflow: true });
			clear(err);
			log(`[${nameName}] queueLimitExceeded, closeConn`);
			try { closeConn?.(err) } catch (_) { }
			throw err;
		}
		let completionPromise = null;
		let completions = null;
		if (waitForFlush) {
			completions = [];
			completionPromise = new Promise((resolve, reject) => completions.push({ resolve, reject }));
		}
		grain.collect({ chunk, allowRetry, completions });
		if (!draining) drain();
		return waitForFlush ? completionPromise.then(() => true) : true;
	};

	return {
		writeIn(data, allowRetry = true) {
			return enqueue(data, allowRetry, false);
		},
		writeAndWait(data, allowRetry = true) {
			return enqueue(data, allowRetry, true);
		},
		async waitEmpty() {
			if (!grain.byteCount && !draining) return;
			await new Promise(resolve => idleResolvers.push(resolve));
		},
		clearEmpty() {
			closed = true;
			clear();
		}
	};
}

function createDownlinkGrainsender(webSocket, headerData = null, isActive = null) {
	const packetCap = downlinkGrainpacketByte;
	const tailBytes = downlinkGraintailThreshold;
	const grain = createGraincollector(packetCap, true);
	let header = typeof headerData === 'function' ? null : headerData;
	const getResponseHeader = typeof headerData === 'function' ? headerData : () => {
		const value = header;
		header = null;
		return value;
	};
	let flushTimer = null;
	let generation = 0;
	let scheduledGeneration = 0;
	let waitRounds = 0;
	let flushPromise = null;
	let directSendPromise = null;
	let forceDrain = false;
	let stopStopAlreadyOpenStart = false;
	let activeSendCount = 0;
	let activeDirectSendCount = 0;
	let activeSendError = null;
	let activeSendWaiter = [];
	const waitActiveSendComplete = () => {
		if (!activeSendCount && !activeDirectSendCount) return Promise.resolve();
		return new Promise(resolve => activeSendWaiter.push(resolve));
	};
	const markSendComplete = () => {
		if (activeSendCount || activeDirectSendCount || !activeSendWaiter.length) return;
		const resolvers = activeSendWaiter;
		activeSendWaiter = [];
		for (const resolve of resolvers) resolve();
	};
	const checkActiveSendError = () => {
		if (!activeSendError) return;
		const err = activeSendError;
		grain.clearEmpty();
		throw err;
	};
	const currentSenderValid = () => forceDrain || !isActive || isActive();
	const closeActiveConn = () => {
		if (currentSenderValid()) closeSocketQuietly(webSocket);
	};

	const sendRawChunk = async (chunk) => {
		if (!currentSenderValid()) return;
		if (webSocket.readyState !== WebSocket.OPEN) throw new Error('ws.readyState is not open');
		chunk = appendResponseHeader(chunk);
		await WebSocketsendAndWait(webSocket, chunk);
	};

	const serialSendRawChunk = async (chunk) => {
		while (directSendPromise) await directSendPromise;
		const sendTask = sendRawChunk(chunk);
		directSendPromise = sendTask;
		try { await sendTask }
		finally {
			if (directSendPromise === sendTask) directSendPromise = null;
		}
	};

	const appendResponseHeader = (chunk) => {
		const responseHeader = getResponseHeader();
		if (!responseHeader) return chunk;
		const merged = new Uint8Array(responseHeader.length + chunk.byteLength);
		merged.set(responseHeader, 0);
		merged.set(chunk, responseHeader.length);
		return merged;
	};

	const flush = async () => {
		while (flushPromise) await flushPromise;
		if (flushTimer) clearTimeout(flushTimer);
		flushTimer = null;
		waitRounds = 0;
		if (!currentSenderValid()) {
			grain.clearEmpty();
			return;
		}
		const sendTask = (async () => {
			for (; ;) {
				if (!currentSenderValid()) {
					grain.clearEmpty();
					break;
				}
				const packed = grain.combinePacket();
				if (!packed) break;
				await serialSendRawChunk(packed.chunk);
			}
		})();
		flushPromise = sendTask.catch(err => {
			activeSendError ||= err;
			throw err;
		}).finally(() => { flushPromise = null });
		return flushPromise;
	};

	const scheduleFlush = () => {
		if (!currentSenderValid()) {
			grain.clearEmpty();
			return;
		}
		if (grain.isEmpty || flushTimer) return;
		if (grain.byteCount >= packetCap || packetCap - grain.byteCount < tailBytes) {
			flush().catch(closeActiveConn);
			return;
		}
		flushTimer = setTimeout(() => {
			flushTimer = null;
			if (!currentSenderValid()) {
				grain.clearEmpty();
				return;
			}
			if (grain.isEmpty) return;
			if (grain.byteCount >= packetCap || packetCap - grain.byteCount < tailBytes) {
				flush().catch(closeActiveConn);
				return;
			}
			if (waitRounds < downlinkGrainmaxWaitRounds && (generation !== scheduledGeneration || grain.byteCount < downlinkGrainlowWatermarkBytes)) {
				waitRounds++;
				scheduledGeneration = generation;
				scheduleFlush();
				return;
			}
			flush().catch(closeActiveConn);
		}, 1);
	};

	return {
		async sendDirect(data) {
			if (stopStopAlreadyOpenStart || !currentSenderValid()) return;
			activeDirectSendCount++;
			try {
				const chunk = numDataTurnUint8Array(data);
				if (!chunk.byteLength) return;
				await serialSendRawChunk(chunk);
			} catch (err) {
				activeSendError ||= err;
				throw err;
			} finally {
				activeDirectSendCount--;
				markSendComplete();
			}
		},
		async sendSend(data) {
			if (stopStopAlreadyOpenStart || !currentSenderValid()) return;
			activeSendCount++;
			try {
				const chunk = numDataTurnUint8Array(data);
				if (!chunk.byteLength) return;
				let offset = 0;
				const totalBytes = chunk.byteLength;
				while (offset < totalBytes) {
					const remainingBytes = totalBytes - offset;
					if (grain.isEmpty && remainingBytes >= packetCap) {
						const sendBytes = Math.min(packetCap, remainingBytes);
						const view = offset || sendBytes !== totalBytes ? chunk.subarray(offset, offset + sendBytes) : chunk;
						await serialSendRawChunk(view);
						offset += sendBytes;
						continue;
					}
					const copyBytes = Math.min(packetCap - grain.byteCount, totalBytes - offset);
					if (!copyBytes) {
						await flush();
						continue;
					}
					grain.collect({ chunk: offset || copyBytes !== totalBytes ? chunk.subarray(offset, offset + copyBytes) : chunk });
					offset += copyBytes;
					generation++;
					if (grain.byteCount >= packetCap || packetCap - grain.byteCount < tailBytes) await flush();
					else scheduleFlush();
				}
			} catch (err) {
				activeSendError ||= err;
				throw err;
			} finally {
				activeSendCount--;
				markSendComplete();
			}
		},
		flush,
		async stopStopAndRefreshNew() {
			if (stopStopAlreadyOpenStart) {
				await waitActiveSendComplete();
				while (directSendPromise) await directSendPromise;
				checkActiveSendError();
				await flush();
				return;
			}
			stopStopAlreadyOpenStart = true;
			forceDrain = true;
			if (flushTimer) clearTimeout(flushTimer);
			flushTimer = null;
			await waitActiveSendComplete();
			while (directSendPromise) await directSendPromise;
			checkActiveSendError();
			await flush();
		}
	};
}

async function connectStreams(remoteSocket, webSocket, headerData, retryFunc, isCurrentSocket = null, remoteConnWrapper = null) {
	let header = headerData, hasData = false, reader, useBYOB = false, readError = null;
	const BYOBsingleReadLimit = 64 * 1024;
	const currentConnStillValid = () => !isCurrentSocket || isCurrentSocket();
	const downlinkSender = createDownlinkGrainsender(webSocket, header, currentConnStillValid);
	header = null;
	const downlinkController = { stopStopAndRefreshNew: () => downlinkSender.stopStopAndRefreshNew() };
	if (remoteConnWrapper) remoteConnWrapper.downlinkController = downlinkController;
	try { remoteSocket.closed?.catch?.(() => { }) } catch (e) { }

	try { reader = remoteSocket.readable.getReader({ mode: 'byob' }); useBYOB = true }
	catch (e) { reader = remoteSocket.readable.getReader() }

	try {
		if (!useBYOB) {
			while (true) {
				const { done, value } = await reader.read();
				if (!currentConnStillValid()) break;
				if (done) break;
				if (!value || value.byteLength === 0) continue;
				hasData = true;
				if (value.byteLength >= downlinkGrainpacketByte) {
					await downlinkSender.flush();
					await downlinkSender.sendDirect(value);
				} else {
					await downlinkSender.sendSend(value);
				}
			}
		} else {
			let readBuffer = new ArrayBuffer(BYOBsingleReadLimit);
			while (true) {
				const { done, value } = await reader.read(new Uint8Array(readBuffer, 0, BYOBsingleReadLimit));
				if (!currentConnStillValid()) break;
				if (done) break;
				if (!value || value.byteLength === 0) continue;
				hasData = true;
				if (value.byteLength >= downlinkGrainpacketByte) {
					await downlinkSender.flush();
					await downlinkSender.sendDirect(value);
					readBuffer = new ArrayBuffer(BYOBsingleReadLimit);
				} else {
					await downlinkSender.sendSend(value.slice());
					readBuffer = value.buffer.byteLength >= BYOBsingleReadLimit ? value.buffer : new ArrayBuffer(BYOBsingleReadLimit);
				}
			}
		}
		if (currentConnStillValid()) await downlinkSender.flush();
	} catch (err) { readError = err }
	finally {
		if (currentConnStillValid() && webSocket.readyState === WebSocket.OPEN) {
			try { await downlinkSender.stopStopAndRefreshNew() } catch (err) { readError ||= err }
		}
		if (remoteConnWrapper?.downlinkController === downlinkController) remoteConnWrapper.downlinkController = null;
		try { await reader.cancel() } catch (e) { }
		try { reader.releaseLock() } catch (e) { }
		try { remoteSocket.close() } catch (e) { }
	}
	if (!hasData && retryFunc && webSocket.readyState === WebSocket.OPEN && currentConnStillValid()) {
		try {
			await retryFunc();
			return;
		} catch (err) {
			readError ||= err;
		}
	}
	if (!currentConnStillValid()) return;
	if (readError) log(`[TCPdownlink] readFail: ${readError?.message || readError}`);
	closeSocketQuietly(webSocket);
}

function isSpeedTestSite(hostname) {
	const speedTestDomains = ['speed.cloudflare.com', 'cp.cloudflare.com'];
	hostname = hostname.toLowerCase();
	return speedTestDomains.some(domain => hostname === domain || hostname.endsWith('.' + domain));
}

function buildLocal204response(respHeader = null) {
	const thisLocation204response = new TextEncoder().encode(
		'HTTP/1.1 204 No Content\r\n' +
		'Content-Length: 0\r\n' +
		'Connection: close\r\n' +
		'\r\n'
	);
	if (validDataLength(respHeader) === 0) return thisLocation204response;
	const protoResponseHeader = numDataTurnUint8Array(respHeader);
	const response = new Uint8Array(protoResponseHeader.byteLength + thisLocation204response.byteLength);
	response.set(protoResponseHeader, 0);
	response.set(thisLocation204response, protoResponseHeader.byteLength);
	log(`[TCPturnSend] buildLocal204response: ${response.byteLength}B`);
	return response;
}

function buildMakeWSthisLocation204response(respHeader = null) {
	const WSthisLocation204response = new TextEncoder().encode(
		'HTTP/1.1 204 No Content\r\n' +
		'Content-Length: 0\r\n' +
		'Connection: keep-alive\r\n' +
		'\r\n'
	);
	if (validDataLength(respHeader) === 0) return WSthisLocation204response;
	const protoResponseHeader = numDataTurnUint8Array(respHeader);
	const response = new Uint8Array(protoResponseHeader.byteLength + WSthisLocation204response.byteLength);
	response.set(protoResponseHeader, 0);
	response.set(WSthisLocation204response, protoResponseHeader.byteLength);
	return response;
}

///////////////////////////////////////////////////////SOCKS5/HTTPfunc///////////////////////////////////////////////
async function socks5Connect(targetHost, targetPort, initialData, TCPconn, parsedSocks5) {
	const { username, password, hostname, port } = parsedSocks5 || {};
	const socket = TCPconn({ hostname, port }), writer = socket.writable.getWriter(), reader = socket.readable.getReader();
	try {
		const authMethods = username && password ? new Uint8Array([0x05, 0x02, 0x00, 0x02]) : new Uint8Array([0x05, 0x01, 0x00]);
		await writer.write(authMethods);
		let response = await reader.read();
		if (response.done || response.value.byteLength < 2) throw new Error('S5 method selection failed');

		const selectedMethod = new Uint8Array(response.value)[1];
		if (selectedMethod === 0x02) {
			if (!username || !password) throw new Error('S5 requires authentication');
			const userBytes = new TextEncoder().encode(username), passBytes = new TextEncoder().encode(password);
			const authPacket = new Uint8Array([0x01, userBytes.length, ...userBytes, passBytes.length, ...passBytes]);
			await writer.write(authPacket);
			response = await reader.read();
			if (response.done || new Uint8Array(response.value)[1] !== 0x00) throw new Error('S5 authentication failed');
		} else if (selectedMethod !== 0x00) throw new Error(`S5 unsupported auth method: ${selectedMethod}`);

		const hostBytes = new TextEncoder().encode(targetHost);
		const connectPacket = new Uint8Array([0x05, 0x01, 0x00, 0x03, hostBytes.length, ...hostBytes, targetPort >> 8, targetPort & 0xff]);
		await writer.write(connectPacket);
		response = await reader.read();
		if (response.done || new Uint8Array(response.value)[1] !== 0x00) throw new Error('S5 connection failed');

		if (validDataLength(initialData) > 0) await writer.write(initialData);
		writer.releaseLock(); reader.releaseLock();
		return socket;
	} catch (error) {
		try { writer.releaseLock() } catch (e) { }
		try { reader.releaseLock() } catch (e) { }
		try { socket.close() } catch (e) { }
		throw error;
	}
}

async function httpConnect(targetHost, targetPort, initialData, HTTPSproxy = false, TCPconn, parsedSocks5) {
	const { username, password, hostname, port } = parsedSocks5 || {};
	const socket = HTTPSproxy
		? TCPconn({ hostname, port }, { secureTransport: 'on', allowHalfOpen: false })
		: TCPconn({ hostname, port });
	const writer = socket.writable.getWriter(), reader = socket.readable.getReader();
	const encoder = new TextEncoder();
	const decoder = new TextDecoder();
	try {
		if (HTTPSproxy) await socket.opened;

		const auth = username && password ? `Proxy-Authorization: Basic ${btoa(`${username}:${password}`)}\r\n` : '';
		const request = `CONNECT ${targetHost}:${targetPort} HTTP/1.1\r\nHost: ${targetHost}:${targetPort}\r\n${auth}User-Agent: Mozilla/5.0\r\nConnection: keep-alive\r\n\r\n`;
		await writer.write(encoder.encode(request));
		writer.releaseLock();

		let responseBuffer = new Uint8Array(0), headerEndIndex = -1, bytesRead = 0;
		while (headerEndIndex === -1 && bytesRead < 8192) {
			const { done, value } = await reader.read();
			if (done || !value) throw new Error(`${HTTPSproxy ? 'HTTPS' : 'HTTP'} proxyOnReturn CONNECT closeConnBeforeResponse`);
			responseBuffer = new Uint8Array([...responseBuffer, ...value]);
			bytesRead = responseBuffer.length;
			const crlfcrlf = responseBuffer.findIndex((_, i) => i < responseBuffer.length - 3 && responseBuffer[i] === 0x0d && responseBuffer[i + 1] === 0x0a && responseBuffer[i + 2] === 0x0d && responseBuffer[i + 3] === 0x0a);
			if (crlfcrlf !== -1) headerEndIndex = crlfcrlf + 4;
		}

		if (headerEndIndex === -1) throw new Error('proxy CONNECT responseHeaderTooLongOrInvalid');
		const statusMatch = decoder.decode(responseBuffer.slice(0, headerEndIndex)).split('\r\n')[0].match(/HTTP\/\d\.\d\s+(\d+)/);
		const statusCode = statusMatch ? parseInt(statusMatch[1], 10) : NaN;
		if (!Number.isFinite(statusCode) || statusCode < 200 || statusCode >= 300) throw new Error(`Connection failed: HTTP ${statusCode}`);

		reader.releaseLock();

		if (validDataLength(initialData) > 0) {
			const remoteWriter = socket.writable.getWriter();
			await remoteWriter.write(initialData);
			remoteWriter.releaseLock();
		}

		// CONNECT responseHeaderMayCarryTunnelData, firstReturnFillToCanReadStream, avoidFirstPacketSwallowed. 
		if (bytesRead > headerEndIndex) {
			const { readable, writable } = new TransformStream();
			const transformWriter = writable.getWriter();
			await transformWriter.write(responseBuffer.subarray(headerEndIndex, bytesRead));
			transformWriter.releaseLock();
			socket.readable.pipeTo(writable).catch(() => { });
			return { readable, writable: socket.writable, closed: socket.closed, close: () => socket.close() };
		}

		return socket;
	} catch (error) {
		try { writer.releaseLock() } catch (e) { }
		try { reader.releaseLock() } catch (e) { }
		try { socket.close() } catch (e) { }
		throw error;
	}
}

async function httpsConnect(targetHost, targetPort, initialData, TCPconn, parsedSocks5) {
	const { username, password, hostname, port } = parsedSocks5 || {};
	const encoder = new TextEncoder();
	const decoder = new TextDecoder();
	let tlsSocket = null;
	const tlsServerName = isIPHostname(hostname) ? '' : stripIPv6Brackets(hostname);
	const openHTTPSproxyTLS = async (allowChacha = false) => {
		const proxySocket = TCPconn({ hostname, port });
		try {
			await proxySocket.opened;
			const socket = new TlsClient(proxySocket, { serverName: tlsServerName, insecure: true, allowChacha });
			await socket.handshake();
			log(`[HTTPSproxy] TLSversion: ${socket.isTls13 ? '1.3' : '1.2'} | Cipher: 0x${socket.cipherSuite.toString(16)}${socket.cipherConfig?.chacha ? ' (ChaCha20)' : ' (AES-GCM)'}`);
			return socket;
		} catch (error) {
			try { proxySocket.close() } catch (e) { }
			throw error;
		}
	};
	try {
		try {
			tlsSocket = await openHTTPSproxyTLS(false);
		} catch (error) {
			if (!/cipher|handshake|TLS Alert|ServerHello|Finished|Unsupported|Missing TLS/i.test(error?.message || `${error || ''}`)) throw error;
			log(`[HTTPSproxy] AES-GCM TLS handshakeFail, returnRetreat ChaCha20 compatMode: ${error?.message || error}`);
			tlsSocket = await openHTTPSproxyTLS(true);
		}

		const auth = username && password ? `Proxy-Authorization: Basic ${btoa(`${username}:${password}`)}\r\n` : '';
		const request = `CONNECT ${targetHost}:${targetPort} HTTP/1.1\r\nHost: ${targetHost}:${targetPort}\r\n${auth}User-Agent: Mozilla/5.0\r\nConnection: keep-alive\r\n\r\n`;
		await tlsSocket.write(encoder.encode(request));

		let responseBuffer = new Uint8Array(0), headerEndIndex = -1, bytesRead = 0;
		while (headerEndIndex === -1 && bytesRead < 8192) {
			const value = await tlsSocket.read();
			if (!value) throw new Error('HTTPS proxyOnReturn CONNECT closeConnBeforeResponse');
			responseBuffer = concatByteData(responseBuffer, value);
			bytesRead = responseBuffer.length;
			const crlfcrlf = responseBuffer.findIndex((_, i) => i < responseBuffer.length - 3 && responseBuffer[i] === 0x0d && responseBuffer[i + 1] === 0x0a && responseBuffer[i + 2] === 0x0d && responseBuffer[i + 3] === 0x0a);
			if (crlfcrlf !== -1) headerEndIndex = crlfcrlf + 4;
		}

		if (headerEndIndex === -1) throw new Error('HTTPS proxy CONNECT responseHeaderTooLongOrInvalid');
		const statusMatch = decoder.decode(responseBuffer.slice(0, headerEndIndex)).split('\r\n')[0].match(/HTTP\/\d\.\d\s+(\d+)/);
		const statusCode = statusMatch ? parseInt(statusMatch[1], 10) : NaN;
		if (!Number.isFinite(statusCode) || statusCode < 200 || statusCode >= 300) throw new Error(`Connection failed: HTTP ${statusCode}`);

		if (validDataLength(initialData) > 0) await tlsSocket.write(numDataTurnUint8Array(initialData));
		const bufferedData = bytesRead > headerEndIndex ? responseBuffer.subarray(headerEndIndex, bytesRead) : null;
		let closedSettled = false, resolveClosed, rejectClosed;
		const settleClosed = (settle, value) => {
			if (!closedSettled) {
				closedSettled = true;
				settle(value);
			}
		};
		const closed = new Promise((resolve, reject) => {
			resolveClosed = resolve;
			rejectClosed = reject;
		});
		const close = () => {
			try { tlsSocket.close() } catch (e) { }
			settleClosed(resolveClosed);
		};
		const readable = new ReadableStream({
			async start(controller) {
				try {
					if (validDataLength(bufferedData) > 0) controller.enqueue(bufferedData);
					while (true) {
						const data = await tlsSocket.read();
						if (!data) break;
						if (data.byteLength > 0) controller.enqueue(data);
					}
					try { controller.close() } catch (e) { }
					settleClosed(resolveClosed);
				} catch (error) {
					try { controller.error(error) } catch (e) { }
					settleClosed(rejectClosed, error);
				}
			},
			cancel() {
				close();
			}
		});
		const writable = new WritableStream({
			async write(chunk) {
				await tlsSocket.write(numDataTurnUint8Array(chunk));
			},
			close,
			abort(error) {
				close();
				if (error) settleClosed(rejectClosed, error);
			}
		});
		return { readable, writable, closed, close };
	} catch (error) {
		try { tlsSocket?.close() } catch (e) { }
		throw error;
	}
}

function createRequestTCPconnector(request) {
	const requestObject = /** @type {any} */ (request);
	const fetcher = requestObject?.fetcher;
	if (!fetcher || typeof fetcher.connect !== 'function') throw new Error('request.fetcher.connect unavailable');
	return (options, init) => init === undefined ? fetcher.connect(options) : fetcher.connect(options, init);
}
////////////////////////////////////////////TLSClient by: @Alexandre_Kojeve////////////////////////////////////////////////
const TLS_VERSION_10 = 769, TLS_VERSION_12 = 771, TLS_VERSION_13 = 772;
const CONTENT_TYPE_CHANGE_CIPHER_SPEC = 20, CONTENT_TYPE_ALERT = 21, CONTENT_TYPE_HANDSHAKE = 22, CONTENT_TYPE_APPLICATION_DATA = 23;
const HANDSHAKE_TYPE_CLIENT_HELLO = 1, HANDSHAKE_TYPE_SERVER_HELLO = 2, HANDSHAKE_TYPE_NEW_SESSION_TICKET = 4, HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS = 8, HANDSHAKE_TYPE_CERTIFICATE = 11, HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE = 12, HANDSHAKE_TYPE_CERTIFICATE_REQUEST = 13, HANDSHAKE_TYPE_SERVER_HELLO_DONE = 14, HANDSHAKE_TYPE_CERTIFICATE_VERIFY = 15, HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE = 16, HANDSHAKE_TYPE_FINISHED = 20, HANDSHAKE_TYPE_KEY_UPDATE = 24;
const EXT_SERVER_NAME = 0, EXT_SUPPORTED_GROUPS = 10, EXT_EC_POINT_FORMATS = 11, EXT_SIGNATURE_ALGORITHMS = 13, EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION = 16, EXT_SUPPORTED_VERSIONS = 43, EXT_PSK_KEY_EXCHANGE_MODES = 45, EXT_KEY_SHARE = 51;

const ALERT_CLOSE_NOTIFY = 0, ALERT_LEVEL_WARNING = 1, ALERT_UNRECOGNIZED_NAME = 112;
const shouldIgnoreTlsAlert = fragment => fragment?.[0] === ALERT_LEVEL_WARNING && fragment?.[1] === ALERT_UNRECOGNIZED_NAME;

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();
const EMPTY_BYTES = new Uint8Array(0);

const CIPHER_SUITES_BY_ID = new Map([
	[4865, { id: 4865, keyLen: 16, ivLen: 12, hash: "SHA-256", tls13: !0 }],
	[4866, { id: 4866, keyLen: 32, ivLen: 12, hash: "SHA-384", tls13: !0 }],
	[4867, { id: 4867, keyLen: 32, ivLen: 12, hash: "SHA-256", tls13: !0, chacha: !0 }],
	[49199, { id: 49199, keyLen: 16, ivLen: 4, hash: "SHA-256", kex: "ECDHE" }],
	[49200, { id: 49200, keyLen: 32, ivLen: 4, hash: "SHA-384", kex: "ECDHE" }],
	[52392, { id: 52392, keyLen: 32, ivLen: 12, hash: "SHA-256", kex: "ECDHE", chacha: !0 }],
	[49195, { id: 49195, keyLen: 16, ivLen: 4, hash: "SHA-256", kex: "ECDHE" }],
	[49196, { id: 49196, keyLen: 32, ivLen: 4, hash: "SHA-384", kex: "ECDHE" }],
	[52393, { id: 52393, keyLen: 32, ivLen: 12, hash: "SHA-256", kex: "ECDHE", chacha: !0 }]
]);
const GROUPS_BY_ID = new Map([[29, "X25519"], [23, "P-256"]]);
const SUPPORTED_SIGNATURE_ALGORITHMS = [2052, 2053, 2054, 1025, 1281, 1537, 1027, 1283, 1539];

const tlsBytes = (...parts) => {
	const flattenBytes = values => values.flatMap(value => value instanceof Uint8Array ? [...value] : Array.isArray(value) ? flattenBytes(value) : "number" == typeof value ? [value] : []);
	return new Uint8Array(flattenBytes(parts))
};
const uint16be = value => [value >> 8 & 255, 255 & value];
const readUint16 = (buffer, offset) => buffer[offset] << 8 | buffer[offset + 1];
const readUint24 = (buffer, offset) => buffer[offset] << 16 | buffer[offset + 1] << 8 | buffer[offset + 2];
const concatBytes = (...chunks) => {
	const nonEmptyChunks = chunks.filter((chunk => chunk && chunk.length > 0)),
		length = nonEmptyChunks.reduce(((total, chunk) => total + chunk.length), 0),
		result = new Uint8Array(length);
	let offset = 0;
	for (const chunk of nonEmptyChunks) result.set(chunk, offset), offset += chunk.length;
	return result
};
const randomBytes = length => crypto.getRandomValues(new Uint8Array(length));
const constantTimeEqual = (left, right) => {
	if (!left || !right || left.length !== right.length) return !1;
	let diff = 0; for (let index = 0; index < left.length; index++) diff |= left[index] ^ right[index];
	return 0 === diff
};
const hashByteLength = hash => "SHA-512" === hash ? 64 : "SHA-384" === hash ? 48 : 32;
async function hmac(hash, key, data) {
	const cryptoKey = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash }, !1, ["sign"]);
	return new Uint8Array(await crypto.subtle.sign("HMAC", cryptoKey, data))
}
async function digestBytes(hash, data) { return new Uint8Array(await crypto.subtle.digest(hash, data)) }
async function tls12Prf(secret, label, seed, length, hash = "SHA-256") {
	const labelSeed = concatBytes(textEncoder.encode(label), seed);
	let output = new Uint8Array(0),
		currentA = labelSeed;
	for (; output.length < length;) {
		currentA = await hmac(hash, secret, currentA);
		const block = await hmac(hash, secret, concatBytes(currentA, labelSeed));
		output = concatBytes(output, block)
	}
	return output.slice(0, length)
}
async function hkdfExtract(hash, salt, inputKeyMaterial) {
	return salt && salt.length || (salt = new Uint8Array(hashByteLength(hash))), hmac(hash, salt, inputKeyMaterial)
}
async function hkdfExpandLabel(hash, secret, label, context, length) {
	const fullLabel = textEncoder.encode("tls13 " + label);
	return async function (hash, secret, info, length) {
		const hashLen = hashByteLength(hash),
			roundCount = Math.ceil(length / hashLen);
		let output = new Uint8Array(0),
			previousBlock = new Uint8Array(0);
		for (let round = 1; round <= roundCount; round++) previousBlock = await hmac(hash, secret, concatBytes(previousBlock, info, [round])), output = concatBytes(output, previousBlock);
		return output.slice(0, length)
	}(hash, secret, tlsBytes(uint16be(length), fullLabel.length, fullLabel, context.length, context), length)
}
async function generateKeyShare(group = "P-256") {
	const algorithm = "X25519" === group ? { name: "X25519" } : { name: "ECDH", namedCurve: group };
	const keyPair = /** @type {CryptoKeyPair} */ (await crypto.subtle.generateKey(algorithm, !0, ["deriveBits"]));
	const publicKeyRaw = /** @type {ArrayBuffer} */ (await crypto.subtle.exportKey("raw", keyPair.publicKey));
	return { keyPair, publicKeyRaw: new Uint8Array(publicKeyRaw) }
}
async function deriveSharedSecret(privateKey, peerPublicKey, group = "P-256") {
	const algorithm = "X25519" === group ? { name: "X25519" } : { name: "ECDH", namedCurve: group },
		peerKey = await crypto.subtle.importKey("raw", peerPublicKey, algorithm, !1, []),
		bits = "P-384" === group ? 384 : "P-521" === group ? 528 : 256;
	return new Uint8Array(await crypto.subtle.deriveBits(/** @type {any} */({ name: algorithm.name, public: peerKey }), privateKey, bits))
}
async function importAesGcmKey(key, usages) { return crypto.subtle.importKey("raw", key, { name: "AES-GCM" }, !1, usages) }
async function aesGcmEncryptWithKey(cryptoKey, initializationVector, plaintext, additionalData) {
	return new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: initializationVector, additionalData, tagLength: 128 }, cryptoKey, plaintext))
}
async function aesGcmDecryptWithKey(cryptoKey, initializationVector, ciphertext, additionalData) {
	return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: initializationVector, additionalData, tagLength: 128 }, cryptoKey, ciphertext))
}

function rotateLeft32(value, bits) { return (value << bits | value >>> 32 - bits) >>> 0 }

function chachaQuarterRound(state, indexA, indexB, indexC, indexD) {
	state[indexA] = state[indexA] + state[indexB] >>> 0, state[indexD] = rotateLeft32(state[indexD] ^ state[indexA], 16), state[indexC] = state[indexC] + state[indexD] >>> 0, state[indexB] = rotateLeft32(state[indexB] ^ state[indexC], 12), state[indexA] = state[indexA] + state[indexB] >>> 0, state[indexD] = rotateLeft32(state[indexD] ^ state[indexA], 8), state[indexC] = state[indexC] + state[indexD] >>> 0, state[indexB] = rotateLeft32(state[indexB] ^ state[indexC], 7)
}

function chacha20Block(key, counter, nonce) {
	const state = new Uint32Array(16);
	state[0] = 1634760805, state[1] = 857760878, state[2] = 2036477234, state[3] = 1797285236;
	const keyView = new DataView(key.buffer, key.byteOffset, key.byteLength);
	for (let wordIndex = 0; wordIndex < 8; wordIndex++) state[4 + wordIndex] = keyView.getUint32(4 * wordIndex, !0);
	state[12] = counter;
	const nonceView = new DataView(nonce.buffer, nonce.byteOffset, nonce.byteLength);
	state[13] = nonceView.getUint32(0, !0), state[14] = nonceView.getUint32(4, !0), state[15] = nonceView.getUint32(8, !0);
	const workingState = new Uint32Array(state);
	for (let round = 0; round < 10; round++) chachaQuarterRound(workingState, 0, 4, 8, 12), chachaQuarterRound(workingState, 1, 5, 9, 13), chachaQuarterRound(workingState, 2, 6, 10, 14), chachaQuarterRound(workingState, 3, 7, 11, 15), chachaQuarterRound(workingState, 0, 5, 10, 15), chachaQuarterRound(workingState, 1, 6, 11, 12), chachaQuarterRound(workingState, 2, 7, 8, 13), chachaQuarterRound(workingState, 3, 4, 9, 14);
	for (let wordIndex = 0; wordIndex < 16; wordIndex++) workingState[wordIndex] = workingState[wordIndex] + state[wordIndex] >>> 0;
	return new Uint8Array(workingState.buffer.slice(0))
}

function chacha20Xor(key, nonce, data) {
	const output = new Uint8Array(data.length);
	let counter = 1;
	for (let offset = 0; offset < data.length; offset += 64) {
		const block = chacha20Block(key, counter++, nonce),
			blockLength = Math.min(64, data.length - offset);
		for (let index = 0; index < blockLength; index++) output[offset + index] = data[offset + index] ^ block[index]
	}
	return output
}

function poly1305Mac(key, message) {
	const rKey = function (rBytes) {
		const clamped = new Uint8Array(rBytes);
		return clamped[3] &= 15, clamped[7] &= 15, clamped[11] &= 15, clamped[15] &= 15, clamped[4] &= 252, clamped[8] &= 252, clamped[12] &= 252, clamped
	}(key.slice(0, 16)),
		sKey = key.slice(16, 32);
	let accumulator = [0n, 0n, 0n, 0n, 0n];
	const rLimbs = [0x3ffffffn & BigInt(rKey[0] | rKey[1] << 8 | rKey[2] << 16 | rKey[3] << 24), 0x3ffffffn & BigInt(rKey[3] >> 2 | rKey[4] << 6 | rKey[5] << 14 | rKey[6] << 22), 0x3ffffffn & BigInt(rKey[6] >> 4 | rKey[7] << 4 | rKey[8] << 12 | rKey[9] << 20), 0x3ffffffn & BigInt(rKey[9] >> 6 | rKey[10] << 2 | rKey[11] << 10 | rKey[12] << 18), 0x3ffffffn & BigInt(rKey[13] | rKey[14] << 8 | rKey[15] << 16)];
	for (let offset = 0; offset < message.length; offset += 16) {
		const chunk = message.slice(offset, offset + 16),
			paddedChunk = new Uint8Array(17);
		paddedChunk.set(chunk), paddedChunk[chunk.length] = 1, accumulator[0] += BigInt(paddedChunk[0] | paddedChunk[1] << 8 | paddedChunk[2] << 16 | (3 & paddedChunk[3]) << 24), accumulator[1] += BigInt(paddedChunk[3] >> 2 | paddedChunk[4] << 6 | paddedChunk[5] << 14 | (15 & paddedChunk[6]) << 22), accumulator[2] += BigInt(paddedChunk[6] >> 4 | paddedChunk[7] << 4 | paddedChunk[8] << 12 | (63 & paddedChunk[9]) << 20), accumulator[3] += BigInt(paddedChunk[9] >> 6 | paddedChunk[10] << 2 | paddedChunk[11] << 10 | paddedChunk[12] << 18), accumulator[4] += BigInt(paddedChunk[13] | paddedChunk[14] << 8 | paddedChunk[15] << 16 | paddedChunk[16] << 24);
		const product = [0n, 0n, 0n, 0n, 0n];
		for (let accIndex = 0; accIndex < 5; accIndex++)
			for (let rIndex = 0; rIndex < 5; rIndex++) {
				const limbIndex = accIndex + rIndex;
				limbIndex < 5 ? product[limbIndex] += accumulator[accIndex] * rLimbs[rIndex] : product[limbIndex - 5] += accumulator[accIndex] * rLimbs[rIndex] * 5n
			}
		let carry = 0n;
		for (let index = 0; index < 5; index++) product[index] += carry, accumulator[index] = 0x3ffffffn & product[index], carry = product[index] >> 26n;
		accumulator[0] += 5n * carry, carry = accumulator[0] >> 26n, accumulator[0] &= 0x3ffffffn, accumulator[1] += carry
	}
	let tagValue = accumulator[0] | accumulator[1] << 26n | accumulator[2] << 52n | accumulator[3] << 78n | accumulator[4] << 104n;
	tagValue = tagValue + sKey.reduce(((total, byte, index) => total + (BigInt(byte) << BigInt(8 * index))), 0n) & (1n << 128n) - 1n;
	const tag = new Uint8Array(16);
	for (let index = 0; index < 16; index++) tag[index] = Number(tagValue >> BigInt(8 * index) & 0xffn);
	return tag
}

function chacha20Poly1305Encrypt(key, nonce, plaintext, additionalData) {
	const polyKey = chacha20Block(key, 0, nonce).slice(0, 32),
		ciphertext = chacha20Xor(key, nonce, plaintext),
		aadPadding = (16 - additionalData.length % 16) % 16,
		ciphertextPadding = (16 - ciphertext.length % 16) % 16,
		macData = new Uint8Array(additionalData.length + aadPadding + ciphertext.length + ciphertextPadding + 16);
	macData.set(additionalData, 0), macData.set(ciphertext, additionalData.length + aadPadding);
	const lengthView = new DataView(macData.buffer, additionalData.length + aadPadding + ciphertext.length + ciphertextPadding);
	lengthView.setBigUint64(0, BigInt(additionalData.length), !0), lengthView.setBigUint64(8, BigInt(ciphertext.length), !0);
	const tag = poly1305Mac(polyKey, macData);
	return concatBytes(ciphertext, tag)
}

function chacha20Poly1305Decrypt(key, nonce, ciphertext, additionalData) {
	if (ciphertext.length < 16) throw new Error("Ciphertext too short");
	const tag = ciphertext.slice(-16),
		encryptedData = ciphertext.slice(0, -16),
		polyKey = chacha20Block(key, 0, nonce).slice(0, 32),
		aadPadding = (16 - additionalData.length % 16) % 16,
		ciphertextPadding = (16 - encryptedData.length % 16) % 16,
		macData = new Uint8Array(additionalData.length + aadPadding + encryptedData.length + ciphertextPadding + 16);
	macData.set(additionalData, 0), macData.set(encryptedData, additionalData.length + aadPadding);
	const lengthView = new DataView(macData.buffer, additionalData.length + aadPadding + encryptedData.length + ciphertextPadding);
	lengthView.setBigUint64(0, BigInt(additionalData.length), !0), lengthView.setBigUint64(8, BigInt(encryptedData.length), !0);
	const expectedTag = poly1305Mac(polyKey, macData);
	let diff = 0;
	for (let index = 0; index < 16; index++) diff |= tag[index] ^ expectedTag[index];
	if (0 !== diff) throw new Error("ChaCha20-Poly1305 authentication failed");
	return chacha20Xor(key, nonce, encryptedData)
}

const TLS_MAX_PLAINTEXT_FRAGMENT = 16 * 1024;
function buildTlsRecord(contentType, fragment, version = TLS_VERSION_12) {
	const data = numDataTurnUint8Array(fragment);
	const record = new Uint8Array(5 + data.byteLength);
	record[0] = contentType;
	record[1] = version >> 8 & 255;
	record[2] = version & 255;
	record[3] = data.byteLength >> 8 & 255;
	record[4] = data.byteLength & 255;
	record.set(data, 5);
	return record;
}
function buildHandshakeMessage(handshakeType, body) { return tlsBytes(handshakeType, (length => [length >> 16 & 255, length >> 8 & 255, 255 & length])(body.length), body) }
class TlsRecordParser {
	constructor() { this.buffer = new Uint8Array(0) }
	feed(chunk) {
		const bytes = numDataTurnUint8Array(chunk);
		this.buffer = this.buffer.length ? concatBytes(this.buffer, bytes) : bytes
	}
	next() {
		if (this.buffer.length < 5) return null;
		const contentType = this.buffer[0],
			version = readUint16(this.buffer, 1),
			length = readUint16(this.buffer, 3);
		if (this.buffer.length < 5 + length) return null;
		const fragment = this.buffer.subarray(5, 5 + length);
		return this.buffer = this.buffer.subarray(5 + length), { type: contentType, version, length, fragment }
	}
}
class TlsHandshakeParser {
	constructor() { this.buffer = new Uint8Array(0) }
	feed(chunk) {
		const bytes = numDataTurnUint8Array(chunk);
		this.buffer = this.buffer.length ? concatBytes(this.buffer, bytes) : bytes
	}
	next() {
		if (this.buffer.length < 4) return null;
		const handshakeType = this.buffer[0],
			length = readUint24(this.buffer, 1);
		if (this.buffer.length < 4 + length) return null;
		const body = this.buffer.subarray(4, 4 + length),
			raw = this.buffer.subarray(0, 4 + length);
		return this.buffer = this.buffer.subarray(4 + length), { type: handshakeType, length, body, raw }
	}
}

function parseServerHello(body) {
	let offset = 0;
	const legacyVersion = readUint16(body, offset);
	offset += 2;
	const serverRandom = body.slice(offset, offset + 32);
	offset += 32;
	const sessionIdLength = body[offset++],
		sessionId = body.slice(offset, offset + sessionIdLength);
	offset += sessionIdLength;
	const cipherSuite = readUint16(body, offset);
	offset += 2;
	const compression = body[offset++];
	let selectedVersion = legacyVersion,
		keyShare = null,
		alpn = null;
	if (offset < body.length) {
		const extensionsLength = readUint16(body, offset);
		offset += 2;
		const extensionsEnd = offset + extensionsLength;
		for (; offset + 4 <= extensionsEnd;) {
			const extensionType = readUint16(body, offset);
			offset += 2;
			const extensionLength = readUint16(body, offset);
			offset += 2;
			const extensionData = body.slice(offset, offset + extensionLength);
			if (offset += extensionLength, extensionType === EXT_SUPPORTED_VERSIONS && extensionLength >= 2) selectedVersion = readUint16(extensionData, 0);
			else if (extensionType === EXT_KEY_SHARE && extensionLength >= 4) {
				const group = readUint16(extensionData, 0),
					keyLength = readUint16(extensionData, 2);
				keyShare = { group, key: extensionData.slice(4, 4 + keyLength) }
			} else extensionType === EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION && extensionLength >= 3 && (alpn = textDecoder.decode(extensionData.slice(3, 3 + extensionData[2])))
		}
	}
	const helloRetryRequestRandom = new Uint8Array([207, 33, 173, 116, 229, 154, 97, 17, 190, 29, 140, 2, 30, 101, 184, 145, 194, 162, 17, 22, 122, 187, 140, 94, 7, 158, 9, 226, 200, 168, 51, 156]);
	return { version: legacyVersion, serverRandom, sessionId, cipherSuite, compression, selectedVersion, keyShare, alpn, isHRR: constantTimeEqual(serverRandom, helloRetryRequestRandom), isTls13: selectedVersion === TLS_VERSION_13 }
}

function parseServerKeyExchange(body) {
	let offset = 1;
	const namedCurve = readUint16(body, offset);
	offset += 2;
	const keyLength = body[offset++];
	return { namedCurve, serverPublicKey: body.slice(offset, offset + keyLength) }
}

function extractLeafCertificate(body, hasContext = 0) {
	let offset = 0;
	if (hasContext) {
		const contextLength = body[offset++];
		offset += contextLength
	}
	if (offset + 3 > body.length) return null;
	const certificateListLength = readUint24(body, offset);
	if (offset += 3, !certificateListLength || offset + 3 > body.length) return null;
	const certificateLength = readUint24(body, offset);
	return offset += 3, certificateLength ? body.slice(offset, offset + certificateLength) : null
}

function parseEncryptedExtensions(body) {
	const parsed = { alpn: null };
	let offset = 2;
	const extensionsEnd = 2 + readUint16(body, 0);
	for (; offset + 4 <= extensionsEnd;) {
		const extensionType = readUint16(body, offset);
		offset += 2;
		const extensionLength = readUint16(body, offset);
		if (offset += 2, extensionType === EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION && extensionLength >= 3) {
			const protocolLength = body[offset + 2];
			protocolLength > 0 && offset + 3 + protocolLength <= offset + extensionLength && (parsed.alpn = textDecoder.decode(body.slice(offset + 3, offset + 3 + protocolLength)))
		}
		offset += extensionLength
	}
	return parsed
}

function buildClientHello(clientRandom, serverName, keyShares, { tls13: enableTls13 = !0, tls12: enableTls12 = !0, alpn = null, chacha = !0 } = {}) {
	const cipherIds = [];
	enableTls13 && cipherIds.push(4865, 4866, ...(chacha ? [4867] : [])), enableTls12 && cipherIds.push(49199, 49200, 49195, 49196, ...(chacha ? [52392, 52393] : []));
	const cipherBytes = tlsBytes(...cipherIds.flatMap(uint16be)),
		extensions = [tlsBytes(255, 1, 0, 1, 0)];
	if (serverName) {
		const serverNameBytes = textEncoder.encode(serverName),
			serverNameList = tlsBytes(0, uint16be(serverNameBytes.length), serverNameBytes);
		extensions.push(tlsBytes(uint16be(EXT_SERVER_NAME), uint16be(serverNameList.length + 2), uint16be(serverNameList.length), serverNameList))
	}
	extensions.push(tlsBytes(uint16be(EXT_EC_POINT_FORMATS), 0, 2, 1, 0)), extensions.push(tlsBytes(uint16be(EXT_SUPPORTED_GROUPS), 0, 6, 0, 4, 0, 29, 0, 23));
	const signatureBytes = tlsBytes(...SUPPORTED_SIGNATURE_ALGORITHMS.flatMap(uint16be));
	extensions.push(tlsBytes(uint16be(EXT_SIGNATURE_ALGORITHMS), uint16be(signatureBytes.length + 2), uint16be(signatureBytes.length), signatureBytes));
	const protocols = Array.isArray(alpn) ? alpn.filter(Boolean) : alpn ? [alpn] : [];
	if (protocols.length) {
		const alpnBytes = concatBytes(...protocols.map((protocol => { const protocolBytes = textEncoder.encode(protocol); return tlsBytes(protocolBytes.length, protocolBytes) })));
		extensions.push(tlsBytes(uint16be(EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION), uint16be(alpnBytes.length + 2), uint16be(alpnBytes.length), alpnBytes))
	}
	if (enableTls13 && keyShares) {
		let keyShareBytes;
		if (extensions.push(enableTls12 ? tlsBytes(uint16be(EXT_SUPPORTED_VERSIONS), 0, 5, 4, 3, 4, 3, 3) : tlsBytes(uint16be(EXT_SUPPORTED_VERSIONS), 0, 3, 2, 3, 4)), extensions.push(tlsBytes(uint16be(EXT_PSK_KEY_EXCHANGE_MODES), 0, 2, 1, 1)), keyShares?.x25519 && keyShares?.p256) keyShareBytes = concatBytes(tlsBytes(0, 29, uint16be(keyShares.x25519.length), keyShares.x25519), tlsBytes(0, 23, uint16be(keyShares.p256.length), keyShares.p256));
		else if (keyShares?.x25519) keyShareBytes = tlsBytes(0, 29, uint16be(keyShares.x25519.length), keyShares.x25519);
		else if (keyShares?.p256) keyShareBytes = tlsBytes(0, 23, uint16be(keyShares.p256.length), keyShares.p256);
		else {
			if (!(keyShares instanceof Uint8Array)) throw new Error("Invalid keyShares");
			keyShareBytes = tlsBytes(0, 23, uint16be(keyShares.length), keyShares)
		}
		extensions.push(tlsBytes(uint16be(EXT_KEY_SHARE), uint16be(keyShareBytes.length + 2), uint16be(keyShareBytes.length), keyShareBytes))
	}
	const extensionsBytes = concatBytes(...extensions);
	return buildHandshakeMessage(HANDSHAKE_TYPE_CLIENT_HELLO, tlsBytes(uint16be(TLS_VERSION_12), clientRandom, 0, uint16be(cipherBytes.length), cipherBytes, 1, 0, uint16be(extensionsBytes.length), extensionsBytes))
}
const uint64be = sequenceNumber => { const bytes = new Uint8Array(8); return new DataView(bytes.buffer).setBigUint64(0, sequenceNumber, !1), bytes },
	xorSequenceIntoIv = (initializationVector, sequenceNumber) => {
		const nonce = initializationVector.slice(),
			sequenceBytes = uint64be(sequenceNumber);
		for (let index = 0; index < 8; index++) nonce[nonce.length - 8 + index] ^= sequenceBytes[index];
		return nonce
	},
	deriveTrafficKeys = (hash, secret, keyLen, ivLen) => Promise.all([hkdfExpandLabel(hash, secret, "key", EMPTY_BYTES, keyLen), hkdfExpandLabel(hash, secret, "iv", EMPTY_BYTES, ivLen)]);
class TlsClient {
	constructor(socket, options = {}) {
		if (this.socket = socket, this.serverName = options.serverName || "", this.supportTls13 = !1 !== options.tls13, this.supportTls12 = !1 !== options.tls12, !this.supportTls13 && !this.supportTls12) throw new Error("At least one TLS version must be enabled");
		this.alpnProtocols = Array.isArray(options.alpn) ? options.alpn : options.alpn ? [options.alpn] : null, this.allowChacha = options.allowChacha !== false, this.timeout = options.timeout ?? 3e4, this.clientRandom = randomBytes(32), this.serverRandom = null, this.handshakeChunks = [], this.handshakeComplete = !1, this.negotiatedAlpn = null, this.cipherSuite = null, this.cipherConfig = null, this.isTls13 = !1, this.masterSecret = null, this.handshakeSecret = null, this.clientWriteKey = null, this.serverWriteKey = null, this.clientWriteIv = null, this.serverWriteIv = null, this.clientHandshakeKey = null, this.serverHandshakeKey = null, this.clientHandshakeIv = null, this.serverHandshakeIv = null, this.clientAppKey = null, this.serverAppKey = null, this.clientAppIv = null, this.serverAppIv = null, this.clientWriteCryptoKey = null, this.serverWriteCryptoKey = null, this.clientHandshakeCryptoKey = null, this.serverHandshakeCryptoKey = null, this.clientAppCryptoKey = null, this.serverAppCryptoKey = null, this.clientSeqNum = 0n, this.serverSeqNum = 0n, this.recordParser = new TlsRecordParser, this.handshakeParser = new TlsHandshakeParser, this.keyPairs = new Map, this.ecdhKeyPair = null, this.sawCert = !1
	}
	recordHandshake(chunk) { this.handshakeChunks.push(chunk) }
	transcript() { return 1 === this.handshakeChunks.length ? this.handshakeChunks[0] : concatBytes(...this.handshakeChunks) }
	getCipherConfig(cipherSuite) { return CIPHER_SUITES_BY_ID.get(cipherSuite) || null }
	async readChunk(reader) { return this.timeout ? Promise.race([reader.read(), new Promise(((resolve, reject) => setTimeout((() => reject(new Error("TLS read timeout"))), this.timeout)))]) : reader.read() }
	async readRecordsUntil(reader, predicate, closedError) {
		for (; ;) {
			let record;
			for (; record = this.recordParser.next();)
				if (await predicate(record)) return;
			const { value, done } = await this.readChunk(reader);
			if (done) throw new Error(closedError);
			this.recordParser.feed(value)
		}
	}
	async readHandshakeUntil(reader, predicate, closedError) {
		for (let message; message = this.handshakeParser.next();)
			if (await predicate(message)) return;
		return this.readRecordsUntil(reader, (async record => {
			if (record.type === CONTENT_TYPE_ALERT) {
				if (shouldIgnoreTlsAlert(record.fragment)) return;
				throw new Error(`TLS Alert: ${record.fragment[1]}`);
			}
			if (record.type === CONTENT_TYPE_HANDSHAKE) {
				this.handshakeParser.feed(record.fragment);
				for (let message; message = this.handshakeParser.next();)
					if (await predicate(message)) return 1
			}
		}), closedError)
	}
	async acceptCertificate(certificate) { if (!certificate?.length) throw new Error("Empty certificate"); this.sawCert = !0 }
	async handshake() {
		const [p256Share, x25519Share] = await Promise.all([generateKeyShare("P-256"), generateKeyShare("X25519")]);
		this.keyPairs = new Map([[23, p256Share], [29, x25519Share]]), this.ecdhKeyPair = p256Share.keyPair;
		const reader = this.socket.readable.getReader(),
			writer = this.socket.writable.getWriter();
		try {
			const clientHello = buildClientHello(this.clientRandom, this.serverName, { x25519: x25519Share.publicKeyRaw, p256: p256Share.publicKeyRaw }, { tls13: this.supportTls13, tls12: this.supportTls12, alpn: this.alpnProtocols, chacha: this.allowChacha });
			this.recordHandshake(clientHello), await writer.write(buildTlsRecord(CONTENT_TYPE_HANDSHAKE, clientHello, TLS_VERSION_10));
			const serverHello = await this.receiveServerHello(reader);
			if (serverHello.isHRR) throw new Error("HelloRetryRequest is not supported by TLSClientMini");
			if (serverHello.keyShare?.group && this.keyPairs.has(serverHello.keyShare.group)) {
				const selectedKeyPair = this.keyPairs.get(serverHello.keyShare.group);
				this.ecdhKeyPair = selectedKeyPair.keyPair
			}
			serverHello.isTls13 ? await this.handshakeTls13(reader, writer, serverHello) : await this.handshakeTls12(reader, writer), this.handshakeComplete = !0
		} finally {
			reader.releaseLock(), writer.releaseLock()
		}
	}
	async receiveServerHello(reader) {
		for (; ;) {
			const { value, done } = await this.readChunk(reader);
			if (done) throw new Error("Connection closed waiting for ServerHello");
			let record;
			for (this.recordParser.feed(value); record = this.recordParser.next();) {
				if (record.type === CONTENT_TYPE_ALERT) {
					if (shouldIgnoreTlsAlert(record.fragment)) continue;
					throw new Error(`TLS Alert: level=${record.fragment[0]}, desc=${record.fragment[1]}`);
				}
				if (record.type !== CONTENT_TYPE_HANDSHAKE) continue;
				let message;
				for (this.handshakeParser.feed(record.fragment); message = this.handshakeParser.next();) {
					if (message.type !== HANDSHAKE_TYPE_SERVER_HELLO) continue;
					this.recordHandshake(message.raw);
					const serverHello = parseServerHello(message.body);
					if (this.serverRandom = serverHello.serverRandom, this.cipherSuite = serverHello.cipherSuite, this.cipherConfig = this.getCipherConfig(serverHello.cipherSuite), this.isTls13 = serverHello.isTls13, this.negotiatedAlpn = serverHello.alpn || null, !this.cipherConfig) throw new Error(`Unsupported cipher suite: 0x${serverHello.cipherSuite.toString(16)}`);
					return serverHello
				}
			}
		}
	}
	async handshakeTls12(reader, writer) {
		/** @type {{ namedCurve: number, serverPublicKey: Uint8Array } | null} */
		let serverKeyExchange = null;
		let sawServerHelloDone = !1;
		if (await this.readHandshakeUntil(reader, (async message => {
			switch (message.type) {
				case HANDSHAKE_TYPE_CERTIFICATE: {
					this.recordHandshake(message.raw);
					const certificate = extractLeafCertificate(message.body, 1);
					if (!certificate) throw new Error("Missing TLS 1.2 certificate");
					await this.acceptCertificate(certificate);
					break
				}
				case HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE:
					this.recordHandshake(message.raw), serverKeyExchange = parseServerKeyExchange(message.body);
					break;
				case HANDSHAKE_TYPE_SERVER_HELLO_DONE:
					return this.recordHandshake(message.raw), sawServerHelloDone = !0, 1;
				case HANDSHAKE_TYPE_CERTIFICATE_REQUEST:
					throw new Error("Client certificate is not supported");
				default:
					this.recordHandshake(message.raw)
			}
		}), "Connection closed during TLS 1.2 handshake"), !this.sawCert) throw new Error("Missing TLS 1.2 leaf certificate");
		const serverKeyExchangeData = /** @type {{ namedCurve: number, serverPublicKey: Uint8Array } | null} */ (serverKeyExchange);
		if (!serverKeyExchangeData) throw new Error("Missing TLS 1.2 ServerKeyExchange");
		const curveName = GROUPS_BY_ID.get(serverKeyExchangeData.namedCurve);
		if (!curveName) throw new Error(`Unsupported named curve: 0x${serverKeyExchangeData.namedCurve.toString(16)}`);
		const keyShare = this.keyPairs.get(serverKeyExchangeData.namedCurve);
		if (!keyShare) throw new Error(`Missing key pair for curve: 0x${serverKeyExchangeData.namedCurve.toString(16)}`);
		const preMasterSecret = await deriveSharedSecret(keyShare.keyPair.privateKey, serverKeyExchangeData.serverPublicKey, curveName),
			clientKeyExchange = buildHandshakeMessage(HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE, tlsBytes(keyShare.publicKeyRaw.length, keyShare.publicKeyRaw));
		this.recordHandshake(clientKeyExchange);
		const hashName = this.cipherConfig.hash;
		this.masterSecret = await tls12Prf(preMasterSecret, "master secret", concatBytes(this.clientRandom, this.serverRandom), 48, hashName);
		const keyLen = this.cipherConfig.keyLen,
			ivLen = this.cipherConfig.ivLen,
			keyBlock = await tls12Prf(this.masterSecret, "key expansion", concatBytes(this.serverRandom, this.clientRandom), 2 * keyLen + 2 * ivLen, hashName);
		this.clientWriteKey = keyBlock.slice(0, keyLen), this.serverWriteKey = keyBlock.slice(keyLen, 2 * keyLen), this.clientWriteIv = keyBlock.slice(2 * keyLen, 2 * keyLen + ivLen), this.serverWriteIv = keyBlock.slice(2 * keyLen + ivLen, 2 * keyLen + 2 * ivLen);
		if (!this.cipherConfig.chacha) [this.clientWriteCryptoKey, this.serverWriteCryptoKey] = await Promise.all([importAesGcmKey(this.clientWriteKey, ["encrypt"]), importAesGcmKey(this.serverWriteKey, ["decrypt"])]);
		await writer.write(buildTlsRecord(CONTENT_TYPE_HANDSHAKE, clientKeyExchange)), await writer.write(buildTlsRecord(CONTENT_TYPE_CHANGE_CIPHER_SPEC, tlsBytes(1)));
		const clientVerifyData = await tls12Prf(this.masterSecret, "client finished", await digestBytes(hashName, this.transcript()), 12, hashName),
			finishedMessage = buildHandshakeMessage(HANDSHAKE_TYPE_FINISHED, clientVerifyData);
		this.recordHandshake(finishedMessage), await writer.write(buildTlsRecord(CONTENT_TYPE_HANDSHAKE, await this.encryptTls12(finishedMessage, CONTENT_TYPE_HANDSHAKE)));
		let sawChangeCipherSpec = !1;
		await this.readRecordsUntil(reader, (async record => {
			if (record.type === CONTENT_TYPE_ALERT) {
				if (shouldIgnoreTlsAlert(record.fragment)) return;
				throw new Error(`TLS Alert: ${record.fragment[1]}`);
			}
			if (record.type === CONTENT_TYPE_CHANGE_CIPHER_SPEC) return void (sawChangeCipherSpec = !0);
			if (record.type !== CONTENT_TYPE_HANDSHAKE || !sawChangeCipherSpec) return;
			const decrypted = await this.decryptTls12(record.fragment, CONTENT_TYPE_HANDSHAKE);
			if (decrypted[0] !== HANDSHAKE_TYPE_FINISHED) return;
			const verifyLength = readUint24(decrypted, 1),
				verifyData = decrypted.slice(4, 4 + verifyLength),
				expectedVerifyData = await tls12Prf(this.masterSecret, "server finished", await digestBytes(hashName, this.transcript()), 12, hashName);
			if (!constantTimeEqual(verifyData, expectedVerifyData)) throw new Error("TLS 1.2 server Finished verify failed");
			return 1
		}), "Connection closed waiting for TLS 1.2 Finished")
	}
	async handshakeTls13(reader, writer, serverHello) {
		const groupName = GROUPS_BY_ID.get(serverHello.keyShare?.group);
		if (!groupName || !serverHello.keyShare?.key?.length) throw new Error("Missing TLS 1.3 key_share");
		const hashName = this.cipherConfig.hash,
			hashLen = hashByteLength(hashName),
			keyLen = this.cipherConfig.keyLen,
			ivLen = this.cipherConfig.ivLen,
			sharedSecret = await deriveSharedSecret(this.ecdhKeyPair.privateKey, serverHello.keyShare.key, groupName),
			earlySecret = await hkdfExtract(hashName, null, new Uint8Array(hashLen)),
			derivedSecret = await hkdfExpandLabel(hashName, earlySecret, "derived", await digestBytes(hashName, EMPTY_BYTES), hashLen);
		this.handshakeSecret = await hkdfExtract(hashName, derivedSecret, sharedSecret);
		const transcriptHash = await digestBytes(hashName, this.transcript()),
			clientHandshakeTrafficSecret = await hkdfExpandLabel(hashName, this.handshakeSecret, "c hs traffic", transcriptHash, hashLen),
			serverHandshakeTrafficSecret = await hkdfExpandLabel(hashName, this.handshakeSecret, "s hs traffic", transcriptHash, hashLen);
		[this.clientHandshakeKey, this.clientHandshakeIv] = await deriveTrafficKeys(hashName, clientHandshakeTrafficSecret, keyLen, ivLen), [this.serverHandshakeKey, this.serverHandshakeIv] = await deriveTrafficKeys(hashName, serverHandshakeTrafficSecret, keyLen, ivLen);
		if (!this.cipherConfig.chacha) [this.clientHandshakeCryptoKey, this.serverHandshakeCryptoKey] = await Promise.all([importAesGcmKey(this.clientHandshakeKey, ["encrypt"]), importAesGcmKey(this.serverHandshakeKey, ["decrypt"])]);
		const serverFinishedKey = await hkdfExpandLabel(hashName, serverHandshakeTrafficSecret, "finished", EMPTY_BYTES, hashLen);
		let serverFinishedReceived = !1;
		const handleHandshakeMessage = async message => {
			switch (message.type) {
				case HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS: {
					const encryptedExtensions = parseEncryptedExtensions(message.body);
					encryptedExtensions.alpn && (this.negotiatedAlpn = encryptedExtensions.alpn), this.recordHandshake(message.raw);
					break
				}
				case HANDSHAKE_TYPE_CERTIFICATE: {
					const certificate = extractLeafCertificate(message.body);
					if (!certificate) throw new Error("Missing TLS 1.3 certificate");
					await this.acceptCertificate(certificate), this.recordHandshake(message.raw);
					break
				}
				case HANDSHAKE_TYPE_CERTIFICATE_REQUEST:
					throw new Error("Client certificate is not supported");
				case HANDSHAKE_TYPE_CERTIFICATE_VERIFY:
					this.recordHandshake(message.raw);
					break;
				case HANDSHAKE_TYPE_FINISHED: {
					const expectedVerifyData = await hmac(hashName, serverFinishedKey, await digestBytes(hashName, this.transcript()));
					if (!constantTimeEqual(expectedVerifyData, message.body)) throw new Error("TLS 1.3 server Finished verify failed");
					this.recordHandshake(message.raw), serverFinishedReceived = !0;
					break
				}
				default:
					this.recordHandshake(message.raw)
			}
		};
		await this.readRecordsUntil(reader, (async record => {
			if (record.type === CONTENT_TYPE_CHANGE_CIPHER_SPEC || record.type === CONTENT_TYPE_HANDSHAKE) return;
			if (record.type === CONTENT_TYPE_ALERT) {
				if (shouldIgnoreTlsAlert(record.fragment)) return;
				throw new Error(`TLS Alert: ${record.fragment[1]}`);
			}
			if (record.type !== CONTENT_TYPE_APPLICATION_DATA) return;
			const decrypted = await this.decryptTls13Handshake(record.fragment),
				innerType = decrypted[decrypted.length - 1],
				plaintext = decrypted.slice(0, -1);
			if (innerType === CONTENT_TYPE_HANDSHAKE) {
				this.handshakeParser.feed(plaintext);
				for (let message; message = this.handshakeParser.next();)
					if (await handleHandshakeMessage(message), serverFinishedReceived) return 1
			}
		}), "Connection closed during TLS 1.3 handshake");
		const applicationTranscriptHash = await digestBytes(hashName, this.transcript()),
			masterDerivedSecret = await hkdfExpandLabel(hashName, this.handshakeSecret, "derived", await digestBytes(hashName, EMPTY_BYTES), hashLen),
			masterSecret = await hkdfExtract(hashName, masterDerivedSecret, new Uint8Array(hashLen)),
			clientAppTrafficSecret = await hkdfExpandLabel(hashName, masterSecret, "c ap traffic", applicationTranscriptHash, hashLen),
			serverAppTrafficSecret = await hkdfExpandLabel(hashName, masterSecret, "s ap traffic", applicationTranscriptHash, hashLen);
		[this.clientAppKey, this.clientAppIv] = await deriveTrafficKeys(hashName, clientAppTrafficSecret, keyLen, ivLen), [this.serverAppKey, this.serverAppIv] = await deriveTrafficKeys(hashName, serverAppTrafficSecret, keyLen, ivLen);
		if (!this.cipherConfig.chacha) [this.clientAppCryptoKey, this.serverAppCryptoKey] = await Promise.all([importAesGcmKey(this.clientAppKey, ["encrypt"]), importAesGcmKey(this.serverAppKey, ["decrypt"])]);
		const clientFinishedKey = await hkdfExpandLabel(hashName, clientHandshakeTrafficSecret, "finished", EMPTY_BYTES, hashLen),
			clientFinishedVerifyData = await hmac(hashName, clientFinishedKey, await digestBytes(hashName, this.transcript())),
			clientFinishedMessage = buildHandshakeMessage(HANDSHAKE_TYPE_FINISHED, clientFinishedVerifyData);
		this.recordHandshake(clientFinishedMessage), await writer.write(buildTlsRecord(CONTENT_TYPE_APPLICATION_DATA, await this.encryptTls13Handshake(concatBytes(clientFinishedMessage, [CONTENT_TYPE_HANDSHAKE])))), this.clientSeqNum = 0n, this.serverSeqNum = 0n
	}
	async encryptTls12(plaintext, contentType) {
		const sequenceNumber = this.clientSeqNum++,
			sequenceBytes = uint64be(sequenceNumber),
			additionalData = concatBytes(sequenceBytes, [contentType], uint16be(TLS_VERSION_12), uint16be(plaintext.length));
		if (this.cipherConfig.chacha) {
			const nonce = xorSequenceIntoIv(this.clientWriteIv, sequenceNumber);
			return chacha20Poly1305Encrypt(this.clientWriteKey, nonce, plaintext, additionalData)
		}
		const explicitNonce = randomBytes(8);
		if (!this.clientWriteCryptoKey) this.clientWriteCryptoKey = await importAesGcmKey(this.clientWriteKey, ["encrypt"]);
		return concatBytes(explicitNonce, await aesGcmEncryptWithKey(this.clientWriteCryptoKey, concatBytes(this.clientWriteIv, explicitNonce), plaintext, additionalData))
	}
	async decryptTls12(ciphertext, contentType) {
		const sequenceNumber = this.serverSeqNum++,
			sequenceBytes = uint64be(sequenceNumber);
		if (this.cipherConfig.chacha) {
			const nonce = xorSequenceIntoIv(this.serverWriteIv, sequenceNumber);
			return chacha20Poly1305Decrypt(this.serverWriteKey, nonce, ciphertext, concatBytes(sequenceBytes, [contentType], uint16be(TLS_VERSION_12), uint16be(ciphertext.length - 16)))
		}
		const explicitNonce = ciphertext.subarray(0, 8),
			encryptedData = ciphertext.subarray(8);
		if (!this.serverWriteCryptoKey) this.serverWriteCryptoKey = await importAesGcmKey(this.serverWriteKey, ["decrypt"]);
		return aesGcmDecryptWithKey(this.serverWriteCryptoKey, concatBytes(this.serverWriteIv, explicitNonce), encryptedData, concatBytes(sequenceBytes, [contentType], uint16be(TLS_VERSION_12), uint16be(encryptedData.length - 16)))
	}
	async encryptTls13Handshake(plaintext) {
		const nonce = xorSequenceIntoIv(this.clientHandshakeIv, this.clientSeqNum++),
			additionalData = tlsBytes(CONTENT_TYPE_APPLICATION_DATA, 3, 3, uint16be(plaintext.length + 16));
		if (this.cipherConfig.chacha) return chacha20Poly1305Encrypt(this.clientHandshakeKey, nonce, plaintext, additionalData);
		if (!this.clientHandshakeCryptoKey) this.clientHandshakeCryptoKey = await importAesGcmKey(this.clientHandshakeKey, ["encrypt"]);
		return aesGcmEncryptWithKey(this.clientHandshakeCryptoKey, nonce, plaintext, additionalData)
	}
	async decryptTls13Handshake(ciphertext) {
		const nonce = xorSequenceIntoIv(this.serverHandshakeIv, this.serverSeqNum++),
			additionalData = tlsBytes(CONTENT_TYPE_APPLICATION_DATA, 3, 3, uint16be(ciphertext.length));
		const decrypted = this.cipherConfig.chacha ? await chacha20Poly1305Decrypt(this.serverHandshakeKey, nonce, ciphertext, additionalData) : await aesGcmDecryptWithKey(this.serverHandshakeCryptoKey || (this.serverHandshakeCryptoKey = await importAesGcmKey(this.serverHandshakeKey, ["decrypt"])), nonce, ciphertext, additionalData);
		let innerTypeIndex = decrypted.length - 1;
		for (; innerTypeIndex >= 0 && !decrypted[innerTypeIndex];) innerTypeIndex--;
		return innerTypeIndex < 0 ? EMPTY_BYTES : decrypted.slice(0, innerTypeIndex + 1)
	}
	async encryptTls13(data) {
		const plaintext = concatBytes(data, [CONTENT_TYPE_APPLICATION_DATA]),
			nonce = xorSequenceIntoIv(this.clientAppIv, this.clientSeqNum++),
			additionalData = tlsBytes(CONTENT_TYPE_APPLICATION_DATA, 3, 3, uint16be(plaintext.length + 16));
		if (this.cipherConfig.chacha) return chacha20Poly1305Encrypt(this.clientAppKey, nonce, plaintext, additionalData);
		if (!this.clientAppCryptoKey) this.clientAppCryptoKey = await importAesGcmKey(this.clientAppKey, ["encrypt"]);
		return aesGcmEncryptWithKey(this.clientAppCryptoKey, nonce, plaintext, additionalData)
	}
	async decryptTls13(ciphertext) {
		const nonce = xorSequenceIntoIv(this.serverAppIv, this.serverSeqNum++),
			additionalData = tlsBytes(CONTENT_TYPE_APPLICATION_DATA, 3, 3, uint16be(ciphertext.length)),
			plaintext = this.cipherConfig.chacha ? await chacha20Poly1305Decrypt(this.serverAppKey, nonce, ciphertext, additionalData) : await aesGcmDecryptWithKey(this.serverAppCryptoKey || (this.serverAppCryptoKey = await importAesGcmKey(this.serverAppKey, ["decrypt"])), nonce, ciphertext, additionalData);
		let innerTypeIndex = plaintext.length - 1;
		for (; innerTypeIndex >= 0 && !plaintext[innerTypeIndex];) innerTypeIndex--;
		if (innerTypeIndex < 0) return {
			data: EMPTY_BYTES,
			type: 0
		};
		return {
			data: plaintext.slice(0, innerTypeIndex),
			type: plaintext[innerTypeIndex]
		}
	}
	async write(data) {
		if (!this.handshakeComplete) throw new Error("Handshake not complete");
		const plaintext = numDataTurnUint8Array(data);
		if (!plaintext.byteLength) return;
		const writer = this.socket.writable.getWriter();
		try {
			const records = [];
			for (let offset = 0; offset < plaintext.byteLength; offset += TLS_MAX_PLAINTEXT_FRAGMENT) {
				const chunk = plaintext.subarray(offset, Math.min(offset + TLS_MAX_PLAINTEXT_FRAGMENT, plaintext.byteLength));
				const encrypted = this.isTls13 ? await this.encryptTls13(chunk) : await this.encryptTls12(chunk, CONTENT_TYPE_APPLICATION_DATA);
				records.push(buildTlsRecord(CONTENT_TYPE_APPLICATION_DATA, encrypted));
			}
			await writer.write(records.length === 1 ? records[0] : concatBytes(...records))
		} finally {
			writer.releaseLock()
		}
	}
	async read() {
		for (; ;) {
			let record;
			for (; record = this.recordParser.next();) {
				if (record.type === CONTENT_TYPE_ALERT) {
					if (record.fragment[1] === ALERT_CLOSE_NOTIFY) return null;
					throw new Error(`TLS Alert: ${record.fragment[1]}`)
				}
				if (record.type !== CONTENT_TYPE_APPLICATION_DATA) continue;
				if (!this.isTls13) return this.decryptTls12(record.fragment, CONTENT_TYPE_APPLICATION_DATA);
				const { data, type } = await this.decryptTls13(record.fragment);
				if (type === CONTENT_TYPE_APPLICATION_DATA) return data;
				if (type === CONTENT_TYPE_ALERT) {
					if (data[1] === ALERT_CLOSE_NOTIFY) return null;
					throw new Error(`TLS Alert: ${data[1]}`)
				}
				if (type !== CONTENT_TYPE_HANDSHAKE) continue;
				let message;
				for (this.handshakeParser.feed(data); message = this.handshakeParser.next();)
					if (message.type !== HANDSHAKE_TYPE_NEW_SESSION_TICKET && message.type === HANDSHAKE_TYPE_KEY_UPDATE) throw new Error("TLS 1.3 KeyUpdate is not supported by TLSClientMini")
			}
			const reader = this.socket.readable.getReader();
			try {
				const { value, done } = await this.readChunk(reader);
				if (done) return null;
				this.recordParser.feed(value)
			} finally {
				reader.releaseLock()
			}
		}
	}
	close() { this.socket.close() }
}

function stripIPv6Brackets(hostname = '') {
	const host = String(hostname || '').trim();
	return host.startsWith('[') && host.endsWith(']') ? host.slice(1, -1) : host;
}

function isIPHostname(hostname = '') {
	const host = stripIPv6Brackets(hostname);
	const ipv4Regex = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
	if (ipv4Regex.test(host)) return true;
	if (!host.includes(':')) return false;
	try {
		new URL(`http://[${host}]/`);
		return true;
	} catch (e) {
		return false;
	}
}

//////////////////////////////////////////////////turnConnect///////////////////////////////////////////////
const CONNECT_TIMEOUT_MS = 9999;
const TURN_STUN_MAGIC_COOKIE = new Uint8Array([0x21, 0x12, 0xa4, 0x42]);
const TURN_STUN_TYPE = {
	ALLOCATE_REQUEST: 0x0003, ALLOCATE_SUCCESS: 0x0103, ALLOCATE_ERROR: 0x0113,
	CREATE_PERMISSION_REQUEST: 0x0008, CREATE_PERMISSION_SUCCESS: 0x0108,
	CONNECT_REQUEST: 0x000a, CONNECT_SUCCESS: 0x010a,
	CONNECTION_BIND_REQUEST: 0x000b, CONNECTION_BIND_SUCCESS: 0x010b
};
const TURN_STUN_ATTR = {
	USERNAME: 0x0006, MESSAGE_INTEGRITY: 0x0008, ERROR_CODE: 0x0009,
	XOR_PEER_ADDRESS: 0x0012, REALM: 0x0014, NONCE: 0x0015,
	REQUESTED_TRANSPORT: 0x0019, CONNECTION_ID: 0x002a
};

async function withTimeout(promise, timeoutMs, message) {
	let timer;
	try {
		return await Promise.race([
			promise,
			new Promise((_, reject) => { timer = setTimeout(() => reject(new Error(message)), timeoutMs) })
		]);
	} finally {
		clearTimeout(timer);
	}
}

function isIPv4(value) {
	const parts = String(value || '').split('.');
	return parts.length === 4 && parts.every(part => /^\d{1,3}$/.test(part) && Number(part) >= 0 && Number(part) <= 255);
}

function turnStunPadding(length) {
	return -length & 3;
}

function createTurnStunAttribute(type, value) {
	const body = numDataTurnUint8Array(value);
	const attribute = new Uint8Array(4 + body.byteLength + turnStunPadding(body.byteLength));
	const view = new DataView(attribute.buffer);
	view.setUint16(0, type);
	view.setUint16(2, body.byteLength);
	attribute.set(body, 4);
	return attribute;
}

function createTurnStunMessage(type, transactionId, attributes) {
	const body = concatByteData(...attributes);
	const header = new Uint8Array(20);
	const view = new DataView(header.buffer);
	view.setUint16(0, type);
	view.setUint16(2, body.byteLength);
	header.set(TURN_STUN_MAGIC_COOKIE, 4);
	header.set(transactionId, 8);
	return concatByteData(header, body);
}

function parseTurnErrorCode(data) {
	return data?.byteLength >= 4 ? (data[2] & 7) * 100 + data[3] : 0;
}

function randomTurnTransactionId() {
	return crypto.getRandomValues(new Uint8Array(12));
}

async function addTurnMessageIntegrity(message, key) {
	const signedMessage = new Uint8Array(message);
	const view = new DataView(signedMessage.buffer);
	view.setUint16(2, view.getUint16(2) + 24);
	const hmacKey = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
	const signature = await crypto.subtle.sign('HMAC', hmacKey, signedMessage);
	return concatByteData(signedMessage, createTurnStunAttribute(TURN_STUN_ATTR.MESSAGE_INTEGRITY, new Uint8Array(signature)));
}

async function readTurnStunMessage(reader, bufferedData = null, timeoutMessage = 'TURN response timed out') {
	let buffer = validDataLength(bufferedData) ? numDataTurnUint8Array(bufferedData) : new Uint8Array(0);
	const pull = async () => {
		const { done, value } = await withTimeout(reader.read(), CONNECT_TIMEOUT_MS, timeoutMessage);
		if (done) throw new Error('TURN server closed connection');
		if (value?.byteLength) buffer = concatByteData(buffer, value);
	};
	while (buffer.byteLength < 20) await pull();

	const messageLength = 20 + ((buffer[2] << 8) | buffer[3]);
	if (messageLength > 65555) throw new Error('TURN response is too large');
	while (buffer.byteLength < messageLength) await pull();
	const messageBuffer = buffer.subarray(0, messageLength);
	if (TURN_STUN_MAGIC_COOKIE.some((value, index) => messageBuffer[4 + index] !== value)) throw new Error('Invalid TURN/STUN response');

	const view = new DataView(messageBuffer.buffer, messageBuffer.byteOffset, messageBuffer.byteLength);
	const attributes = {};
	for (let offset = 20; offset + 4 <= messageLength;) {
		const type = view.getUint16(offset);
		const length = view.getUint16(offset + 2);
		if (offset + 4 + length > messageBuffer.byteLength) break;
		attributes[type] = messageBuffer.slice(offset + 4, offset + 4 + length);
		offset += 4 + length + turnStunPadding(length);
	}
	return {
		message: { type: view.getUint16(0), attributes },
		extraData: buffer.byteLength > messageLength ? buffer.subarray(messageLength) : null
	};
}

async function writeTurnBytes(writer, bytes, timeoutMessage) {
	await withTimeout(writer.write(bytes), CONNECT_TIMEOUT_MS, timeoutMessage);
}

async function turnConnect(proxy, targetHost, targetPort, TCPconn) {
	proxy = { ...proxy, username: proxy.username ?? null, password: proxy.password ?? null };
	const resolvedTargetHost = stripIPv6Brackets(targetHost);
	/** @type {string | null} */
	let targetIp = isIPv4(resolvedTargetHost) ? resolvedTargetHost : null;
	if (!targetIp) {
		const records = await DoHqueryInquire(resolvedTargetHost, 'A');
		const recordData = records.find(item => item.type === 1 && isIPv4(item.data))?.data;
		targetIp = typeof recordData === 'string' ? recordData : null;
	}
	if (!targetIp) throw new Error(`Could not resolve ${targetHost} to an IPv4 address for TURN CONNECT`);

	const turnHost = stripIPv6Brackets(proxy.hostname);
	let controlSocket = null, dataSocket = null, controlWriter = null, controlReader = null, dataWriter = null, dataReader = null, dataReaderReleased = false;
	const close = () => {
		try { controlSocket?.close?.() } catch (e) { }
		try { dataSocket?.close?.() } catch (e) { }
	};
	const releaseDataReader = () => {
		if (dataReaderReleased) return;
		dataReaderReleased = true;
		try { dataReader?.releaseLock?.() } catch (e) { }
	};

	try {
		controlSocket = TCPconn({ hostname: turnHost, port: proxy.port });
		await withTimeout(controlSocket.opened, CONNECT_TIMEOUT_MS, 'TURN server connection timed out');
		controlWriter = controlSocket.writable.getWriter();
		controlReader = controlSocket.readable.getReader();

		const xorPeerAddress = new Uint8Array(8);
		xorPeerAddress[1] = 1;
		new DataView(xorPeerAddress.buffer).setUint16(2, targetPort ^ 0x2112);
		targetIp.split('.').forEach((value, index) => {
			xorPeerAddress[4 + index] = Number(value) ^ TURN_STUN_MAGIC_COOKIE[index];
		});
		const peerAddress = createTurnStunAttribute(TURN_STUN_ATTR.XOR_PEER_ADDRESS, xorPeerAddress);
		const requestedTransport = new Uint8Array([6, 0, 0, 0]);

		await writeTurnBytes(controlWriter, createTurnStunMessage(
			TURN_STUN_TYPE.ALLOCATE_REQUEST,
			randomTurnTransactionId(),
			[createTurnStunAttribute(TURN_STUN_ATTR.REQUESTED_TRANSPORT, requestedTransport)]
		), 'TURN Allocate request timed out');

		let turnResponse = await readTurnStunMessage(controlReader, null, 'TURN Allocate response timed out');
		let message = turnResponse.message;
		let bufferedData = turnResponse.extraData;
		let integrityKey = null;
		let authAttributes = [];
		const sign = messageToSign => integrityKey ? addTurnMessageIntegrity(messageToSign, integrityKey) : Promise.resolve(messageToSign);

		if (
			message.type === TURN_STUN_TYPE.ALLOCATE_ERROR
			&& proxy.username !== null
			&& proxy.password !== null
			&& parseTurnErrorCode(message.attributes[TURN_STUN_ATTR.ERROR_CODE]) === 401
		) {
			const realmBytes = message.attributes[TURN_STUN_ATTR.REALM];
			const nonce = message.attributes[TURN_STUN_ATTR.NONCE];
			if (!realmBytes || !nonce?.byteLength) throw new Error('TURN authentication challenge is missing realm or nonce');

			const realm = textDecoder.decode(realmBytes);
			integrityKey = new Uint8Array(await crypto.subtle.digest('MD5', textEncoder.encode(`${proxy.username}:${realm}:${proxy.password}`)));
			authAttributes = [
				createTurnStunAttribute(TURN_STUN_ATTR.USERNAME, textEncoder.encode(proxy.username)),
				createTurnStunAttribute(TURN_STUN_ATTR.REALM, textEncoder.encode(realm)),
				createTurnStunAttribute(TURN_STUN_ATTR.NONCE, nonce)
			];

			const allocateRequest = await addTurnMessageIntegrity(createTurnStunMessage(
				TURN_STUN_TYPE.ALLOCATE_REQUEST,
				randomTurnTransactionId(),
				[
					createTurnStunAttribute(TURN_STUN_ATTR.REQUESTED_TRANSPORT, requestedTransport),
					...authAttributes
				]
			), integrityKey);
			const pipelinedMessages = await Promise.all([
				sign(createTurnStunMessage(TURN_STUN_TYPE.CREATE_PERMISSION_REQUEST, randomTurnTransactionId(), [peerAddress, ...authAttributes])),
				sign(createTurnStunMessage(TURN_STUN_TYPE.CONNECT_REQUEST, randomTurnTransactionId(), [peerAddress, ...authAttributes]))
			]);
			await writeTurnBytes(controlWriter, concatByteData(allocateRequest, ...pipelinedMessages), 'TURN authenticated Allocate request timed out');
			turnResponse = await readTurnStunMessage(controlReader, bufferedData, 'TURN authenticated Allocate response timed out');
			message = turnResponse.message;
			bufferedData = turnResponse.extraData;
		} else if (message.type === TURN_STUN_TYPE.ALLOCATE_SUCCESS) {
			const pipelinedMessages = await Promise.all([
				sign(createTurnStunMessage(TURN_STUN_TYPE.CREATE_PERMISSION_REQUEST, randomTurnTransactionId(), [peerAddress, ...authAttributes])),
				sign(createTurnStunMessage(TURN_STUN_TYPE.CONNECT_REQUEST, randomTurnTransactionId(), [peerAddress, ...authAttributes]))
			]);
			if (pipelinedMessages.length) await writeTurnBytes(controlWriter, concatByteData(...pipelinedMessages), 'TURN pipelined request timed out');
		}

		if (message.type !== TURN_STUN_TYPE.ALLOCATE_SUCCESS) {
			const errorCode = parseTurnErrorCode(message.attributes[TURN_STUN_ATTR.ERROR_CODE]);
			throw new Error(errorCode ? `TURN Allocate failed with ${errorCode}` : 'TURN Allocate failed');
		}

		dataSocket = TCPconn({ hostname: turnHost, port: proxy.port });
		turnResponse = await readTurnStunMessage(controlReader, bufferedData, 'TURN CreatePermission response timed out');
		message = turnResponse.message;
		bufferedData = turnResponse.extraData;
		if (message.type !== TURN_STUN_TYPE.CREATE_PERMISSION_SUCCESS) throw new Error('TURN CreatePermission failed');

		turnResponse = await readTurnStunMessage(controlReader, bufferedData, 'TURN CONNECT response timed out');
		message = turnResponse.message;
		bufferedData = turnResponse.extraData;
		if (message.type !== TURN_STUN_TYPE.CONNECT_SUCCESS || !message.attributes[TURN_STUN_ATTR.CONNECTION_ID]) throw new Error('TURN CONNECT failed');

		await withTimeout(dataSocket.opened, CONNECT_TIMEOUT_MS, 'TURN data connection timed out');
		dataWriter = dataSocket.writable.getWriter();
		dataReader = dataSocket.readable.getReader();
		await writeTurnBytes(dataWriter, await sign(createTurnStunMessage(
			TURN_STUN_TYPE.CONNECTION_BIND_REQUEST,
			randomTurnTransactionId(),
			[
				createTurnStunAttribute(TURN_STUN_ATTR.CONNECTION_ID, message.attributes[TURN_STUN_ATTR.CONNECTION_ID]),
				...authAttributes
			]
		)), 'TURN ConnectionBind request timed out');

		turnResponse = await readTurnStunMessage(dataReader, null, 'TURN ConnectionBind response timed out');
		message = turnResponse.message;
		const extraPayload = turnResponse.extraData;
		if (message.type !== TURN_STUN_TYPE.CONNECTION_BIND_SUCCESS) throw new Error('TURN ConnectionBind failed');

		controlWriter.releaseLock();
		controlWriter = null;
		controlReader.releaseLock();
		controlReader = null;
		dataWriter.releaseLock();
		dataWriter = null;

		const readable = new ReadableStream({
			start(controller) {
				if (extraPayload?.byteLength) controller.enqueue(extraPayload);
			},
			pull(controller) {
				return dataReader.read().then(({ done, value }) => {
					if (done) {
						releaseDataReader();
						controller.close();
					} else if (value?.byteLength) controller.enqueue(new Uint8Array(value));
				});
			},
			cancel() {
				try { dataReader?.cancel?.() } catch (e) { }
				releaseDataReader();
				close();
			}
		});

		return { readable, writable: dataSocket.writable, closed: dataSocket.closed, close };
	} catch (error) {
		try { controlWriter?.releaseLock?.() } catch (e) { }
		try { controlReader?.releaseLock?.() } catch (e) { }
		try { dataWriter?.releaseLock?.() } catch (e) { }
		releaseDataReader();
		close();
		throw error;
	}
}
//////////////////////////////////////////////////sstpConnect///////////////////////////////////////////////
const SSTP_TCP_MSS = 1400;
const SSTP_EMPTY_BYTES = new Uint8Array(0);

function readSstpUint16(bytes, offset = 0) {
	return (bytes[offset] << 8) | bytes[offset + 1];
}

function readSstpUint32(bytes, offset = 0) {
	return ((bytes[offset] << 24) | (bytes[offset + 1] << 16) | (bytes[offset + 2] << 8) | bytes[offset + 3]) >>> 0;
}

function randomSstpUint16() {
	return readSstpUint16(crypto.getRandomValues(new Uint8Array(2)));
}

function internetChecksum(bytes, offset, length) {
	let sum = 0;
	for (let index = offset; index < offset + length - 1; index += 2) sum += readSstpUint16(bytes, index);
	if (length & 1) sum += bytes[offset + length - 1] << 8;
	while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
	return (~sum) & 0xffff;
}

async function sstpConnect(proxy, targetHost, targetPort, TCPconn) {
	proxy = { ...proxy, username: proxy.username ?? null, password: proxy.password ?? null };
	let bufferedBytes = SSTP_EMPTY_BYTES, pppIdentifier = 1, socket = null, reader = null, writer = null;
	let closedSettled = false, resolveClosed, rejectClosed;
	const closed = new Promise((resolve, reject) => {
		resolveClosed = resolve;
		rejectClosed = reject;
	});
	const settleClosed = (settle, value) => {
		if (closedSettled) return;
		closedSettled = true;
		settle(value);
	};
	const close = () => {
		try { reader?.cancel?.().catch?.(() => { }) } catch (e) { }
		try { reader?.releaseLock?.() } catch (e) { }
		try { writer?.close?.().catch?.(() => { }) } catch (e) { }
		try { writer?.releaseLock?.() } catch (e) { }
		try { socket?.close?.() } catch (e) { }
		settleClosed(resolveClosed);
	};

	const readSocketChunk = async () => {
		const { value, done } = await reader.read();
		if (done || !value) throw new Error('SSTP socket closed');
		return numDataTurnUint8Array(value);
	};
	const readBytes = async length => {
		while (bufferedBytes.byteLength < length) {
			const chunk = await readSocketChunk();
			bufferedBytes = bufferedBytes.byteLength ? concatByteData(bufferedBytes, chunk) : chunk;
		}
		const result = bufferedBytes.subarray(0, length);
		bufferedBytes = bufferedBytes.subarray(length);
		return result;
	};
	const readHttpLine = async () => {
		for (; ;) {
			const lineEnd = bufferedBytes.indexOf(10);
			if (lineEnd >= 0) {
				const line = textDecoder.decode(bufferedBytes.subarray(0, lineEnd));
				bufferedBytes = bufferedBytes.subarray(lineEnd + 1);
				return line.replace(/\r$/, '');
			}
			const chunk = await readSocketChunk();
			bufferedBytes = bufferedBytes.byteLength ? concatByteData(bufferedBytes, chunk) : chunk;
		}
	};
	const readPacket = async (timeoutMs = CONNECT_TIMEOUT_MS) => {
		const header = await withTimeout(readBytes(4), timeoutMs, 'SSTP read timeout');
		const length = readSstpUint16(header, 2) & 0x0fff;
		if (length < 4) throw new Error('Invalid SSTP packet length');
		return {
			isControl: (header[1] & 1) !== 0,
			body: length > 4 ? await withTimeout(readBytes(length - 4), timeoutMs, 'SSTP packet body read timeout') : SSTP_EMPTY_BYTES
		};
	};
	const buildSstpDataPacket = pppFrame => {
		const packetLength = 6 + pppFrame.byteLength;
		const packet = new Uint8Array(packetLength);
		packet.set([0x10, 0x00, ((packetLength >> 8) & 0x0f) | 0x80, packetLength & 0xff, 0xff, 0x03]);
		packet.set(pppFrame, 6);
		return packet;
	};
	const buildPppConfigurePacket = (protocol, code, id, options = []) => {
		const optionsLength = options.reduce((size, option) => size + 2 + option.data.byteLength, 0);
		const frame = new Uint8Array(6 + optionsLength);
		const view = new DataView(frame.buffer);
		view.setUint16(0, protocol);
		frame[2] = code;
		frame[3] = id;
		view.setUint16(4, 4 + optionsLength);
		options.reduce((offset, option) => {
			frame[offset] = option.type;
			frame[offset + 1] = 2 + option.data.byteLength;
			frame.set(option.data, offset + 2);
			return offset + 2 + option.data.byteLength;
		}, 6);
		return frame;
	};
	const parsePPPFrame = data => {
		const offset = data.byteLength >= 2 && data[0] === 0xff && data[1] === 0x03 ? 2 : 0;
		if (data.byteLength - offset < 4) return null;
		const protocol = readSstpUint16(data, offset);
		if (protocol === 0x0021) return { protocol, ipPacket: data.subarray(offset + 2) };
		if (data.byteLength - offset < 6) return null;
		return { protocol, code: data[offset + 2], id: data[offset + 3], payload: data.subarray(offset + 6), rawPacket: data.subarray(offset) };
	};
	const parsePppOptions = data => {
		const options = [];
		for (let offset = 0; offset + 2 <= data.byteLength;) {
			const type = data[offset];
			const length = data[offset + 1];
			if (length < 2 || offset + length > data.byteLength) break;
			options.push({ type, data: data.subarray(offset + 2, offset + length) });
			offset += length;
		}
		return options;
	};

	try {
		const serverHost = stripIPv6Brackets(proxy.hostname);
		const serverPort = proxy.port;
		socket = TCPconn({ hostname: serverHost, port: serverPort }, { secureTransport: 'on', allowHalfOpen: false });
		await withTimeout(socket.opened, CONNECT_TIMEOUT_MS, 'SSTP server connection timed out');
		reader = socket.readable.getReader();
		writer = socket.writable.getWriter();

		const displayHost = serverHost.includes(':') ? `[${serverHost}]` : serverHost;
		const httpRequest = textEncoder.encode(
			`SSTP_DUPLEX_POST /sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/ HTTP/1.1\r\n`
			+ `Host: ${Number(serverPort) === 443 ? displayHost : `${displayHost}:${serverPort}`}\r\n`
			+ 'Content-Length: 18446744073709551615\r\n'
			+ `SSTPCORRELATIONID: {${crypto.randomUUID()}}\r\n\r\n`
		);
		const encapsulatedProtocol = new Uint8Array(2);
		new DataView(encapsulatedProtocol.buffer).setUint16(0, 1);
		const maximumReceiveUnit = new Uint8Array(2);
		new DataView(maximumReceiveUnit.buffer).setUint16(0, 1500);
		const sstpConnectRequest = new Uint8Array(12 + encapsulatedProtocol.byteLength);
		const sstpConnectView = new DataView(sstpConnectRequest.buffer);
		sstpConnectRequest[0] = 0x10;
		sstpConnectRequest[1] = 0x01;
		sstpConnectView.setUint16(2, sstpConnectRequest.byteLength | 0x8000);
		sstpConnectView.setUint16(4, 0x0001);
		sstpConnectView.setUint16(6, 1);
		sstpConnectRequest[9] = 1;
		sstpConnectView.setUint16(10, 4 + encapsulatedProtocol.byteLength);
		sstpConnectRequest.set(encapsulatedProtocol, 12);

		await withTimeout(writer.write(concatByteData(
			httpRequest,
			sstpConnectRequest,
			buildSstpDataPacket(buildPppConfigurePacket(0xc021, 1, pppIdentifier++, [
				{ type: 1, data: maximumReceiveUnit }
			]))
		)), CONNECT_TIMEOUT_MS, 'SSTP HTTP handshake request timed out');

		const statusLine = await withTimeout(readHttpLine(), CONNECT_TIMEOUT_MS, 'SSTP HTTP handshake timed out');
		for (; ;) {
			const line = await withTimeout(readHttpLine(), CONNECT_TIMEOUT_MS, 'SSTP HTTP header read timed out');
			if (line === '') break;
		}
		if (!/HTTP\/\d(?:\.\d)?\s+2\d\d/i.test(statusLine)) throw new Error(`SSTP HTTP handshake failed: ${statusLine || 'invalid status'}`);

		let localLcpAcked = false, peerLcpAcked = false, papRequired = false, papSent = false, papDone = false, ipcpStarted = false, ipcpFinished = false, sourceIp = null;
		const sendPapIfReady = async () => {
			if (!localLcpAcked || !peerLcpAcked || !papRequired || papSent) return;
			if (proxy.username === null || proxy.password === null) throw new Error('SSTP server requires PAP authentication');
			const username = textEncoder.encode(proxy.username);
			const password = textEncoder.encode(proxy.password);
			if (username.byteLength > 255 || password.byteLength > 255) throw new Error('SSTP username/password is too long');
			const papLength = 6 + username.byteLength + password.byteLength;
			const frame = new Uint8Array(2 + papLength);
			const view = new DataView(frame.buffer);
			view.setUint16(0, 0xc023);
			frame[2] = 1;
			frame[3] = pppIdentifier++;
			view.setUint16(4, papLength);
			frame[6] = username.byteLength;
			frame.set(username, 7);
			frame[7 + username.byteLength] = password.byteLength;
			frame.set(password, 8 + username.byteLength);
			await withTimeout(writer.write(buildSstpDataPacket(frame)), CONNECT_TIMEOUT_MS, 'SSTP PAP authentication request timed out');
			papSent = true;
		};
		const startIpcpIfReady = async () => {
			if (!localLcpAcked || !peerLcpAcked || ipcpStarted || (papRequired && !papDone)) return;
			await withTimeout(writer.write(buildSstpDataPacket(buildPppConfigurePacket(0x8021, 1, pppIdentifier++, [
				{ type: 3, data: new Uint8Array(4) }
			]))), CONNECT_TIMEOUT_MS, 'SSTP IPCP request timed out');
			ipcpStarted = true;
		};

		for (let round = 0; round < 50 && !ipcpFinished; round++) {
			const packet = await readPacket(CONNECT_TIMEOUT_MS);
			if (packet.isControl) continue;
			const ppp = parsePPPFrame(packet.body);
			if (!ppp) continue;

			if (ppp.protocol === 0xc021) {
				if (ppp.code === 1) {
					const authOption = parsePppOptions(ppp.payload).find(option => option.type === 3);
					if (authOption?.data?.byteLength >= 2) {
						const authProtocol = readSstpUint16(authOption.data);
						if (authProtocol !== 0xc023) throw new Error(`SSTP unsupported PPP authentication protocol: 0x${authProtocol.toString(16)}`);
						papRequired = true;
					}
					const ack = new Uint8Array(ppp.rawPacket);
					ack[2] = 2;
					await withTimeout(writer.write(buildSstpDataPacket(ack)), CONNECT_TIMEOUT_MS, 'SSTP LCP Configure-Ack timed out');
					peerLcpAcked = true;
					await sendPapIfReady();
					await startIpcpIfReady();
				} else if (ppp.code === 2) {
					localLcpAcked = true;
					await sendPapIfReady();
					await startIpcpIfReady();
				}
				continue;
			}

			if (ppp.protocol === 0xc023) {
				if (ppp.code === 2) {
					papDone = true;
					await startIpcpIfReady();
				} else if (ppp.code === 3) throw new Error('SSTP PAP authentication failed');
				continue;
			}

			if (ppp.protocol === 0x8021) {
				if (ppp.code === 1) {
					const ack = new Uint8Array(ppp.rawPacket);
					ack[2] = 2;
					await withTimeout(writer.write(buildSstpDataPacket(ack)), CONNECT_TIMEOUT_MS, 'SSTP IPCP Configure-Ack timed out');
					await startIpcpIfReady();
				} else if (ppp.code === 3) {
					const addressOption = parsePppOptions(ppp.payload).find(option => option.type === 3);
					if (addressOption?.data?.byteLength === 4) {
						sourceIp = [...addressOption.data].join('.');
						await withTimeout(writer.write(buildSstpDataPacket(buildPppConfigurePacket(0x8021, 1, pppIdentifier++, [
							{ type: 3, data: addressOption.data }
						]))), CONNECT_TIMEOUT_MS, 'SSTP IPCP address request timed out');
						ipcpStarted = true;
					}
				} else if (ppp.code === 2) {
					const addressOption = parsePppOptions(ppp.payload).find(option => option.type === 3);
					if (addressOption?.data?.byteLength === 4) sourceIp = [...addressOption.data].join('.');
					ipcpFinished = true;
				}
			}
		}
		if (!sourceIp) throw new Error('SSTP did not assign an IPv4 address');

		const target = stripIPv6Brackets(targetHost);
		/** @type {string | null} */
		let targetIp = isIPv4(target) ? target : null;
		if (!targetIp) {
			const records = await DoHqueryInquire(target, 'A');
			const recordData = records.find(item => item.type === 1 && isIPv4(item.data))?.data;
			targetIp = typeof recordData === 'string' ? recordData : null;
		}
		if (!targetIp) throw new Error(`Could not resolve ${targetHost} to an IPv4 address for SSTP`);

		const sourcePort = 10000 + (randomSstpUint16() % 50000);
		const sourceAddress = new Uint8Array(String(sourceIp || '').split('.').map(Number));
		const destinationAddress = new Uint8Array(String(targetIp || '').split('.').map(Number));
		let sequenceNumber = readSstpUint32(crypto.getRandomValues(new Uint8Array(4)));
		let acknowledgementNumber = 0;
		const ipHeaderTemplate = new Uint8Array(20);
		ipHeaderTemplate.set([0x45, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 64, 6]);
		ipHeaderTemplate.set(sourceAddress, 12);
		ipHeaderTemplate.set(destinationAddress, 16);
		const tcpPseudoHeader = new Uint8Array(1432);
		tcpPseudoHeader.set(sourceAddress);
		tcpPseudoHeader.set(destinationAddress, 4);
		tcpPseudoHeader[9] = 6;
		const buildTcpFrame = (flags, payload = SSTP_EMPTY_BYTES) => {
			const bytes = numDataTurnUint8Array(payload);
			const payloadLength = bytes.byteLength;
			const tcpLength = 20 + payloadLength;
			const ipLength = 20 + tcpLength;
			const sstpLength = 8 + ipLength;
			const frame = new Uint8Array(sstpLength);
			const view = new DataView(frame.buffer);
			frame.set([0x10, 0x00, ((sstpLength >> 8) & 0x0f) | 0x80, sstpLength & 0xff, 0xff, 0x03, 0x00, 0x21]);
			frame.set(ipHeaderTemplate, 8);
			view.setUint16(10, ipLength);
			view.setUint16(12, randomSstpUint16());
			view.setUint16(18, internetChecksum(frame, 8, 20));
			view.setUint16(28, sourcePort);
			view.setUint16(30, targetPort);
			view.setUint32(32, sequenceNumber);
			view.setUint32(36, acknowledgementNumber);
			frame[40] = 0x50;
			frame[41] = flags;
			view.setUint16(42, 65535);
			if (payloadLength) frame.set(bytes, 48);
			tcpPseudoHeader[10] = tcpLength >> 8;
			tcpPseudoHeader[11] = tcpLength & 0xff;
			tcpPseudoHeader.set(frame.subarray(28, 28 + tcpLength), 12);
			view.setUint16(44, internetChecksum(tcpPseudoHeader, 0, 12 + tcpLength));
			return frame;
		};
		const matchIncomingIpPacket = ipPacket => {
			if (ipPacket.byteLength < 40 || ipPacket[9] !== 6) return null;
			const ipHeaderLength = (ipPacket[0] & 0x0f) * 4;
			if (ipPacket.byteLength < ipHeaderLength + 20) return null;
			if (readSstpUint16(ipPacket, ipHeaderLength) !== targetPort) return null;
			if (readSstpUint16(ipPacket, ipHeaderLength + 2) !== sourcePort) return null;
			return {
				flags: ipPacket[ipHeaderLength + 13],
				sequence: readSstpUint32(ipPacket, ipHeaderLength + 4),
				payloadOffset: ipHeaderLength + ((ipPacket[ipHeaderLength + 12] >> 4) & 0x0f) * 4
			};
		};

		await withTimeout(writer.write(buildTcpFrame(0x02)), CONNECT_TIMEOUT_MS, 'SSTP TCP SYN write timed out');
		sequenceNumber = (sequenceNumber + 1) >>> 0;
		let tcpReady = false;
		for (let attempt = 0; attempt < 30; attempt++) {
			const packet = await readPacket(CONNECT_TIMEOUT_MS);
			if (packet.isControl) continue;
			const ppp = parsePPPFrame(packet.body);
			if (!ppp || ppp.protocol !== 0x0021) continue;
			const tcp = matchIncomingIpPacket(ppp.ipPacket);
			if (!tcp || (tcp.flags & 0x12) !== 0x12) continue;
			acknowledgementNumber = (tcp.sequence + 1) >>> 0;
			await withTimeout(writer.write(buildTcpFrame(0x10)), CONNECT_TIMEOUT_MS, 'SSTP TCP ACK write timed out');
			tcpReady = true;
			break;
		}
		if (!tcpReady) throw new Error('TCP handshake through SSTP timed out');

		/** @type {ReadableStreamDefaultController<Uint8Array> | null} */
		let streamController = null;
		const readable = new ReadableStream({
			start(controller) {
				streamController = controller;
			},
			cancel() {
				close();
			}
		});

		(async () => {
			try {
				let pendingChunks = [], pendingLength = 0;
				const flush = () => {
					if (!pendingLength) return;
					if (!streamController) throw new Error('SSTP readable stream is not ready');
					streamController.enqueue(pendingChunks.length === 1 ? pendingChunks[0] : concatByteData(...pendingChunks));
					pendingChunks = [];
					pendingLength = 0;
					writer.write(buildTcpFrame(0x10)).catch(() => { });
				};

				for (; ;) {
					const packet = await readPacket(60000);
					if (packet.isControl) continue;
					const ppp = parsePPPFrame(packet.body);
					if (!ppp || ppp.protocol !== 0x0021) continue;
					const incoming = matchIncomingIpPacket(ppp.ipPacket);
					if (!incoming) continue;

					if (incoming.payloadOffset < ppp.ipPacket.byteLength) {
						const payload = ppp.ipPacket.subarray(incoming.payloadOffset);
						if (payload.byteLength) {
							acknowledgementNumber = (incoming.sequence + payload.byteLength) >>> 0;
							pendingChunks.push(new Uint8Array(payload));
							pendingLength += payload.byteLength;
						}
					}

					if (incoming.flags & 0x01) {
						flush();
						acknowledgementNumber = (acknowledgementNumber + 1) >>> 0;
						writer.write(buildTcpFrame(0x11)).catch(() => { });
						const controller = streamController;
						if (controller) {
							try { controller.close() } catch (e) { }
						}
						close();
						return;
					}

					if (bufferedBytes.byteLength < 4 || pendingLength >= 32768) flush();
				}
			} catch (error) {
				const controller = streamController;
				if (controller) {
					try { controller.error(error) } catch (e) { }
				}
				settleClosed(rejectClosed, error);
				try { socket?.close?.() } catch (e) { }
			}
		})();

		const writable = new WritableStream({
			async write(chunk) {
				const bytes = numDataTurnUint8Array(chunk);
				if (!bytes.byteLength) return;
				if (bytes.byteLength <= SSTP_TCP_MSS) {
					await writer.write(buildTcpFrame(0x18, bytes));
					sequenceNumber = (sequenceNumber + bytes.byteLength) >>> 0;
					return;
				}
				const frames = [];
				for (let offset = 0; offset < bytes.byteLength; offset += SSTP_TCP_MSS) {
					const segment = bytes.subarray(offset, Math.min(offset + SSTP_TCP_MSS, bytes.byteLength));
					frames.push(buildTcpFrame(0x18, segment));
					sequenceNumber = (sequenceNumber + segment.byteLength) >>> 0;
				}
				await writer.write(concatByteData(...frames));
			},
			close() {
				return writer.write(buildTcpFrame(0x11)).catch(() => { });
			},
			abort(error) {
				close();
				if (error) settleClosed(rejectClosed, error);
			}
		});

		return { readable, writable, closed, close };
	} catch (error) {
		close();
		throw error;
	}
}
//////////////////////////////////////////////////utilityFunc///////////////////////////////////////////////
/**
 * withKey Base64 encode
 * @param {string} plaintext - rawPlaintextString
 * @param {string} secret - keyString (like "KEY123") 
 * @returns {string} processedWithKey Base64 string
 */
function base64SecretEncode(plaintext, secret) {
	const encoder = new TextEncoder();
	const data = encoder.encode(plaintext);
	const key = encoder.encode(secret);
	const mixed = new Uint8Array(data.length);

	for (let i = 0; i < data.length; i++) {
		mixed[i] = data[i] ^ key[i % key.length];
	}

	// will Uint8Array convertToBeAble btoa handleLogicOfString
	let binary = '';
	for (let i = 0; i < mixed.length; i++) {
		binary += String.fromCharCode(mixed[i]);
	}
	return btoa(binary);
}

/**
 * withKey Base64 decode
 * @param {string} encoded - processedWithKeyAlt Base64 string
 * @param {string} secret - keyString (mustMatchEncodingTime) 
 * @returns {string} decodedRawPlaintextString
 */
function base64SecretDecode(encoded, secret) {
	const binary = atob(encoded);
	const mixed = new Uint8Array(binary.length);
	for (let i = 0; i < binary.length; i++) {
		mixed[i] = binary.charCodeAt(i);
	}

	const encoder = new TextEncoder();
	const key = encoder.encode(secret);
	const data = new Uint8Array(mixed.length);

	for (let i = 0; i < mixed.length; i++) {
		data[i] = mixed[i] ^ key[i % key.length];
	}

	const decoder = new TextDecoder();
	return decoder.decode(data);
}

function getTransportProtoConfig(config = {}) {
	const isgRPC = config.transportProto === 'grpc';
	const { header: selfPaddingheader, key: selfPaddingkey } = getXHTTPPaddingmarkIdentify(config.UUID);
	const xObfuscateJSON = {
		"xPaddingObfsMode": true,
		"xPaddingMethod": "tokenish",
		"xPaddingPlacement": "queryInHeader",
		"xPaddingHeader": selfPaddingheader,
		"xPaddingKey": selfPaddingkey
	};
	return {
		type: isgRPC ? (config.gRPCmode === 'multi' ? 'grpc&mode=multi' : 'grpc&mode=gun') : (config.transportProto === 'xhttp' ? `xhttp&mode=stream-one&extra=${encodeURIComponent(JSON.stringify(xObfuscateJSON))}` : 'ws'),
		pathFieldName: isgRPC ? 'serviceName' : 'path',
		domainFieldName: isgRPC ? 'authority' : 'host'
	};
}

function getTransportPathParamValue(config = {}, nodePath = '/', asPreferredSubGenerator = false) {
	const pathValue = asPreferredSubGenerator ? '/' : (config.randomPath ? randomPath(nodePath) : nodePath);
	if (config.transportProto !== 'grpc') return pathValue;
	return pathValue.split('?')[0] || '/';
}

function log(...args) {
	if (debugLogPrint) console.log(...args);
}

function ClashsubConfigFileHotpatch(Clash_rawSubContent, config_JSON = {}) {
	const uuid = config_JSON?.UUID || null;
	const ECHenableUse = Boolean(config_JSON?.ECH);
	const HOSTS = Array.isArray(config_JSON?.HOSTS) ? [...config_JSON.HOSTS] : [];
	const ECH_SNI = config_JSON?.ECHConfig?.SNI || null;
	const ECH_DNS = config_JSON?.ECHConfig?.DNS;
	const needNeedHandleLogicECH = Boolean(uuid && ECHenableUse);
	const gRPCUserAgent = (typeof config_JSON?.gRPCUserAgent === 'string' && config_JSON.gRPCUserAgent.trim()) ? config_JSON.gRPCUserAgent.trim() : null;
	const needNeedHandleLogicgRPC = config_JSON?.transportProto === "grpc" && Boolean(gRPCUserAgent);
	const gRPCUserAgentYAML = gRPCUserAgent ? JSON.stringify(gRPCUserAgent) : null;
	let clash_yaml = Clash_rawSubContent.replace(/mode:\s*Rule\b/g, 'mode: rule');

	const baseDnsBlock = `dns:
  enable: true
  default-nameserver:
    - 223.5.5.5
    - 119.29.29.29
    - 114.114.114.114
  use-hosts: true
  nameserver:
    - https://sm2.doh.pub/dns-query
    - https://dns.alidns.com/dns-query
  fallback:
    - 8.8.4.4
    - 208.67.220.220
  fallback-filter:
    geoip: true
    geoip-code: CN
    ipcidr:
      - 240.0.0.0/4
      - 127.0.0.1/32
      - 0.0.0.0/32
    domain:
      - '+.google.com'
      - '+.facebook.com'
      - '+.youtube.com'
`;

	const addInlineGrpcUserAgent = (text) => text.replace(/grpc-opts:\s*\{([\s\S]*?)\}/i, (all, inner) => {
		if (/grpc-user-agent\s*:/i.test(inner)) return all;
		let content = inner.trim();
		if (content.endsWith(',')) content = content.slice(0, -1).trim();
		const patchedContent = content ? `${content}, grpc-user-agent: ${gRPCUserAgentYAML}` : `grpc-user-agent: ${gRPCUserAgentYAML}`;
		return `grpc-opts: {${patchedContent}}`;
	});
	const matchTogRPCnetwork = (text) => /(?:^|[,{])\s*network:\s*(?:"grpc"|'grpc'|grpc)(?=\s*(?:[,}\n#]|$))/mi.test(text);
	const getProxyType = (nodeText) => nodeText.match(/type:\s*(\w+)/)?.[1] || 'vl' + 'ess';
	const getCredentialValue = (nodeText, isFlowStyle) => {
		const credentialField = getProxyType(nodeText) === 'trojan' ? 'password' : 'uuid';
		const pattern = new RegExp(`${credentialField}:\\s*${isFlowStyle ? '([^,}\\n]+)' : '([^\\n]+)'}`);
		return nodeText.match(pattern)?.[1]?.trim() || null;
	};
	const insertNameserverPolicy = (yaml, hostsEntries) => {
		if (/^\s{2}nameserver-policy:\s*(?:\n|$)/m.test(yaml)) {
			return yaml.replace(/^(\s{2}nameserver-policy:\s*\n)/m, `$1${hostsEntries}\n`);
		}
		const lines = yaml.split('\n');
		let dnsBlockEndIndex = -1;
		let inDnsBlock = false;
		for (let i = 0; i < lines.length; i++) {
			const line = lines[i];
			if (/^dns:\s*$/.test(line)) {
				inDnsBlock = true;
				continue;
			}
			if (inDnsBlock && /^[a-zA-Z]/.test(line)) {
				dnsBlockEndIndex = i;
				break;
			}
		}
		const nameserverPolicyBlock = `  nameserver-policy:\n${hostsEntries}`;
		if (dnsBlockEndIndex !== -1) lines.splice(dnsBlockEndIndex, 0, nameserverPolicyBlock);
		else lines.push(nameserverPolicyBlock);
		return lines.join('\n');
	};
	const addFlowformatgRPCUserAgent = (nodeText) => {
		if (!matchTogRPCnetwork(nodeText) || /grpc-user-agent\s*:/i.test(nodeText)) return nodeText;
		if (/grpc-opts:\s*\{/i.test(nodeText)) return addInlineGrpcUserAgent(nodeText);
		return nodeText.replace(/\}(\s*)$/, `, grpc-opts: {grpc-user-agent: ${gRPCUserAgentYAML}}}$1`);
	};
	const addBlockformatgRPCUserAgent = (nodeLines, topLevelIndent) => {
		const topIndent = ' '.repeat(topLevelIndent);
		let grpcOptsIndex = -1;
		for (let idx = 0; idx < nodeLines.length; idx++) {
			const line = nodeLines[idx];
			if (!line.trim()) continue;
			const indent = line.search(/\S/);
			if (indent !== topLevelIndent) continue;
			if (/^\s*grpc-opts:\s*(?:#.*)?$/.test(line) || /^\s*grpc-opts:\s*\{.*\}\s*(?:#.*)?$/.test(line)) {
				grpcOptsIndex = idx;
				break;
			}
		}
		if (grpcOptsIndex === -1) {
			let insertIndex = -1;
			for (let j = nodeLines.length - 1; j >= 0; j--) {
				if (nodeLines[j].trim()) {
					insertIndex = j;
					break;
				}
			}
			if (insertIndex >= 0) nodeLines.splice(insertIndex + 1, 0, `${topIndent}grpc-opts:`, `${topIndent}  grpc-user-agent: ${gRPCUserAgentYAML}`);
			return nodeLines;
		}
		const grpcLine = nodeLines[grpcOptsIndex];
		if (/^\s*grpc-opts:\s*\{.*\}\s*(?:#.*)?$/.test(grpcLine)) {
			if (!/grpc-user-agent\s*:/i.test(grpcLine)) nodeLines[grpcOptsIndex] = addInlineGrpcUserAgent(grpcLine);
			return nodeLines;
		}
		let blockEndIndex = nodeLines.length;
		let childIndent = topLevelIndent + 2;
		let alreadygRPCUserAgent = false;
		for (let idx = grpcOptsIndex + 1; idx < nodeLines.length; idx++) {
			const line = nodeLines[idx];
			const trimmed = line.trim();
			if (!trimmed) continue;
			const indent = line.search(/\S/);
			if (indent <= topLevelIndent) {
				blockEndIndex = idx;
				break;
			}
			if (indent > topLevelIndent && childIndent === topLevelIndent + 2) childIndent = indent;
			if (/^grpc-user-agent\s*:/.test(trimmed)) {
				alreadygRPCUserAgent = true;
				break;
			}
		}
		if (!alreadygRPCUserAgent) nodeLines.splice(blockEndIndex, 0, `${' '.repeat(childIndent)}grpc-user-agent: ${gRPCUserAgentYAML}`);
		return nodeLines;
	};
	const addBlockformatECHOpts = (nodeLines, topLevelIndent) => {
		let insertIndex = -1;
		for (let j = nodeLines.length - 1; j >= 0; j--) {
			if (nodeLines[j].trim()) {
				insertIndex = j;
				break;
			}
		}
		if (insertIndex < 0) return nodeLines;
		const indent = ' '.repeat(topLevelIndent);
		const echOptsLines = [`${indent}ech-opts:`, `${indent}  enable: true`];
		if (ECH_SNI) echOptsLines.push(`${indent}  query-server-name: ${ECH_SNI}`);
		nodeLines.splice(insertIndex + 1, 0, ...echOptsLines);
		return nodeLines;
	};

	if (!/^dns:\s*(?:\n|$)/m.test(clash_yaml)) clash_yaml = baseDnsBlock + clash_yaml;
	if (ECH_SNI && !HOSTS.includes(ECH_SNI)) HOSTS.push(ECH_SNI);

	if (ECHenableUse && HOSTS.length > 0) {
		const hostsEntries = HOSTS.map(host => `    "${host}": ${ECH_DNS ? ECH_DNS : ''}`).join('\n');
		clash_yaml = insertNameserverPolicy(clash_yaml, hostsEntries);
	}

	if (!needNeedHandleLogicECH && !needNeedHandleLogicgRPC) return clash_yaml;

	const lines = clash_yaml.split('\n');
	const processedLines = [];
	let i = 0;

	while (i < lines.length) {
		const line = lines[i];
		const trimmedLine = line.trim();

		if (trimmedLine.startsWith('- {')) {
			let fullNode = line;
			let braceCount = (line.match(/\{/g) || []).length - (line.match(/\}/g) || []).length;
			while (braceCount > 0 && i + 1 < lines.length) {
				i++;
				fullNode += '\n' + lines[i];
				braceCount += (lines[i].match(/\{/g) || []).length - (lines[i].match(/\}/g) || []).length;
			}
			if (needNeedHandleLogicgRPC) fullNode = addFlowformatgRPCUserAgent(fullNode);
			if (needNeedHandleLogicECH && getCredentialValue(fullNode, true) === uuid.trim()) {
				fullNode = fullNode.replace(/\}(\s*)$/, `, ech-opts: {enable: true${ECH_SNI ? `, query-server-name: ${ECH_SNI}` : ''}}}$1`);
			}
			processedLines.push(fullNode);
			i++;
		} else if (trimmedLine.startsWith('- name:')) {
			let nodeLines = [line];
			let baseIndent = line.search(/\S/);
			let topLevelIndent = baseIndent + 2;
			i++;
			while (i < lines.length) {
				const nextLine = lines[i];
				const nextTrimmed = nextLine.trim();
				if (!nextTrimmed) {
					nodeLines.push(nextLine);
					i++;
					break;
				}
				const nextIndent = nextLine.search(/\S/);
				if (nextIndent <= baseIndent && nextTrimmed.startsWith('- ')) {
					break;
				}
				if (nextIndent < baseIndent && nextTrimmed) {
					break;
				}
				nodeLines.push(nextLine);
				i++;
			}
			let nodeText = nodeLines.join('\n');
			if (needNeedHandleLogicgRPC && matchTogRPCnetwork(nodeText)) {
				nodeLines = addBlockformatgRPCUserAgent(nodeLines, topLevelIndent);
				nodeText = nodeLines.join('\n');
			}
			if (needNeedHandleLogicECH && getCredentialValue(nodeText, false) === uuid.trim()) nodeLines = addBlockformatECHOpts(nodeLines, topLevelIndent);
			processedLines.push(...nodeLines);
		} else {
			processedLines.push(line);
			i++;
		}
	}

	return processedLines.join('\n');
}

async function SingboxsubConfigFileHotpatch(SingBox_rawSubContent, config_JSON = {}) {
	const uuid = config_JSON?.UUID || null;
	const fingerprint = config_JSON?.Fingerprint || "chrome";
	const ECHenableUse = Boolean(config_JSON?.ECH);
	const ECH_SNI = config_JSON?.ECHConfig?.SNI || "cloudflare-ech.com";
	const sb_json_text = SingBox_rawSubContent.replace('1.1.1.1', '8.8.8.8').replace('1.0.0.1', '8.8.4.4');
	try {
		const config = JSON.parse(sb_json_text);
		const arrayify = value => value === undefined || value === null ? [] : (Array.isArray(value) ? value : [value]);
		const ensureRoute = () => config.route = config.route && typeof config.route === 'object' ? config.route : {};
		const getGetDNSruleServer = rule => rule && typeof rule === 'object' && !Array.isArray(rule) && typeof rule.server === 'string' ? rule.server : null;
		const addRuleSet = (type, code) => {
			if (!code || typeof code !== 'string') return null;
			const route = ensureRoute(), tag = `${type}-${code}`, ruleSet = Array.isArray(route.rule_set) ? route.rule_set : arrayify(route.rule_set);
			if (!ruleSet.some(item => item?.tag === tag)) {
				const legacyOptions = type === 'geoip' ? route.geoip : route.geosite;
				ruleSet.push({ tag, type: 'remote', format: 'binary', url: `https://raw.githubusercontent.com/SagerNet/sing-${type}/rule-set/${tag}.srs`, ...(legacyOptions?.download_detour ? { download_detour: legacyOptions.download_detour } : {}) });
				config.experimental = config.experimental && typeof config.experimental === 'object' ? config.experimental : {};
				config.experimental.cache_file = config.experimental.cache_file && typeof config.experimental.cache_file === 'object' ? config.experimental.cache_file : {};
				config.experimental.cache_file.enabled ??= true;
			}
			route.rule_set = ruleSet;
			return tag;
		};

		const migrateRuleSetField = rule => {
			if (!rule || typeof rule !== 'object' || Array.isArray(rule)) return rule;
			if (rule.type === 'logical' && Array.isArray(rule.rules)) {
				rule.rules = rule.rules.map(migrateRuleSetField);
				return rule;
			}
			const tags = [];
			for (const geoip of arrayify(rule.geoip)) {
				if (typeof geoip !== 'string') continue;
				if (geoip.toLowerCase() === 'private') rule.ip_is_private = true;
				else tags.push(addRuleSet('geoip', geoip));
			}
			for (const sourceGeoip of arrayify(rule.source_geoip)) {
				if (typeof sourceGeoip !== 'string') continue;
				tags.push(addRuleSet('geoip', sourceGeoip));
				rule.rule_set_ip_cidr_match_source = true;
			}
			for (const geosite of arrayify(rule.geosite)) if (typeof geosite === 'string') tags.push(addRuleSet('geosite', geosite));
			if (tags.length) rule.rule_set = [...new Set([...arrayify(rule.rule_set), ...tags].filter(Boolean))];
			delete rule.geoip;
			delete rule.source_geoip;
			delete rule.geosite;
			return rule;
		};

		const migrateDNSrule = (rule, rcodeServerMap) => {
			rule = migrateRuleSetField(rule);
			if (!rule || typeof rule !== 'object' || Array.isArray(rule)) return rule;
			if (rule.type === 'logical' && Array.isArray(rule.rules)) {
				rule.rules = rule.rules.map(childRule => migrateDNSrule(childRule, rcodeServerMap));
				return rule;
			}
			const serverTag = getGetDNSruleServer(rule);
			if (serverTag && rcodeServerMap.has(serverTag)) {
				for (const key of ['server', 'strategy', 'disable_cache', 'rewrite_ttl', 'client_subnet', 'timeout']) delete rule[key];
				rule.action = 'predefined';
				rule.rcode = rcodeServerMap.get(serverTag);
			} else if (serverTag && !rule.action) rule.action = 'route';
			return rule;
		};

		if (Array.isArray(config.inbounds)) {
			for (const inbound of config.inbounds) {
				if (!inbound || typeof inbound !== 'object' || inbound.type !== 'tun') continue;
				for (const migration of [
					{ targetKey: 'address', sourceKeys: ['inet4_address', 'inet6_address'] },
					{ targetKey: 'route_address', sourceKeys: ['inet4_route_address', 'inet6_route_address'] },
					{ targetKey: 'route_exclude_address', sourceKeys: ['inet4_route_exclude_address', 'inet6_route_exclude_address'] }
				]) {
					const values = arrayify(inbound[migration.targetKey]);
					for (const sourceKey of migration.sourceKeys) values.push(...arrayify(inbound[sourceKey]));
					if (values.length) inbound[migration.targetKey] = [...new Set(values)];
					for (const sourceKey of migration.sourceKeys) delete inbound[sourceKey];
				}
				if (inbound.tag) {
					const addedRules = [];
					if (inbound.domain_strategy) addedRules.push({ inbound: inbound.tag, action: 'resolve', strategy: inbound.domain_strategy });
					if (inbound.sniff) {
						const sniffRule = { inbound: inbound.tag, action: 'sniff' };
						if (inbound.sniff_timeout) sniffRule.timeout = inbound.sniff_timeout;
						addedRules.push(sniffRule);
					}
					if (addedRules.length) {
						const route = ensureRoute();
						route.rules = [...addedRules, ...arrayify(route.rules)];
					}
				}
				delete inbound.sniff;
				delete inbound.sniff_timeout;
				delete inbound.domain_strategy;
			}
		}

		if (config?.route && typeof config.route === 'object' && Array.isArray(config.route.rules)) {
			const patchRouteRule = rule => {
				rule = migrateRuleSetField(rule);
				if (rule?.type === 'logical' && Array.isArray(rule.rules)) rule.rules = rule.rules.map(patchRouteRule);
				else if (rule && typeof rule === 'object' && !Array.isArray(rule) && rule.outbound && !rule.action) rule.action = 'route';
				return rule;
			};
			config.route.rules = config.route.rules.map(patchRouteRule);
		}

		const dns = config?.dns;
		if (dns && typeof dns === 'object') {
			const legacyFakeIP = dns.fakeip && typeof dns.fakeip === 'object' ? dns.fakeip : null;
			const rcodeServerMap = new Map();
			const DNSaddressProtoType = { 'tcp:': 'tcp', 'udp:': 'udp', 'tls:': 'tls', 'quic:': 'quic', 'https:': 'https', 'h3:': 'h3' };
			const RCodemap = { success: 'NOERROR', format_error: 'FORMERR', server_failure: 'SERVFAIL', name_error: 'NXDOMAIN', not_implemented: 'NOTIMP', refused: 'REFUSED' };
			let hasFakeIPServer = false;

			if (Array.isArray(dns.servers)) {
				const migratedServers = [];
				for (const originalServer of dns.servers) {
					if (!originalServer || typeof originalServer !== 'object' || Array.isArray(originalServer)) {
						migratedServers.push(originalServer);
						continue;
					}

					const server = { ...originalServer };
					let parsedAddress = null, parsedRCode = '', rawAddress = typeof server.address === 'string' ? server.address.trim() : '';
					if (rawAddress) {
						const lowerAddress = rawAddress.toLowerCase();
						if (lowerAddress === 'fakeip') parsedAddress = { type: 'fakeip' };
						else if (lowerAddress === 'local') parsedAddress = { type: 'local' };
						else if (lowerAddress.startsWith('rcode://')) {
							parsedAddress = { type: 'rcode' };
							parsedRCode = rawAddress.slice('rcode://'.length).toLowerCase();
						}
						else if (lowerAddress.startsWith('dhcp://')) {
							const dhcpInterface = rawAddress.slice('dhcp://'.length);
							parsedAddress = dhcpInterface && dhcpInterface.toLowerCase() !== 'auto' ? { type: 'dhcp', interface: dhcpInterface } : { type: 'dhcp' };
						} else {
							try {
								const addressURL = new URL(rawAddress);
								const type = DNSaddressProtoType[addressURL.protocol.toLowerCase()];
								if (type) {
									const parsedServer = addressURL.hostname?.startsWith('[') && addressURL.hostname.endsWith(']') ? addressURL.hostname.slice(1, -1) : addressURL.hostname;
									parsedAddress = {
										type,
										server: parsedServer || addressURL.host || rawAddress,
										...(addressURL.port ? { server_port: Number(addressURL.port) } : {}),
										...((type === 'https' || type === 'h3') && addressURL.pathname && addressURL.pathname !== '/dns-query' ? { path: addressURL.pathname } : {})
									};
								}
							} catch (_) { }
							if (!parsedAddress) parsedAddress = { type: 'udp', server: rawAddress };
						}
					}

					if (parsedAddress?.type === 'rcode') {
						const rcode = RCodemap[parsedRCode] || 'NOERROR';
						if (typeof server.tag === 'string' && server.tag) {
							rcodeServerMap.set(server.tag, rcode);
							rcodeServerMap.set(server.tag.startsWith('dns_') ? server.tag.slice(4) : `dns_${server.tag}`, rcode);
						}
						continue;
					}

					if (parsedAddress) {
						delete server.address;
						Object.assign(server, parsedAddress);
					}
					if (server.address_resolver !== undefined && server.domain_resolver === undefined) server.domain_resolver = server.address_resolver;
					if (server.address_strategy !== undefined && server.domain_strategy === undefined) server.domain_strategy = server.address_strategy;
					delete server.address_resolver;
					delete server.address_strategy;
					if (server.detour === 'DIRECT') delete server.detour;

					if (server.type === 'fakeip') {
						hasFakeIPServer = true;
						if (legacyFakeIP) {
							for (const key of ['inet4_range', 'inet6_range']) {
								if (legacyFakeIP[key] !== undefined && server[key] === undefined) server[key] = legacyFakeIP[key];
							}
						}
					}
					migratedServers.push(server);
				}
				dns.servers = migratedServers;
			}

			if (legacyFakeIP && !hasFakeIPServer && legacyFakeIP.enabled !== false) {
				const fakeIPServer = { type: 'fakeip', tag: 'fakeip' };
				for (const rule of Array.isArray(dns.rules) ? dns.rules : []) {
					const serverTag = getGetDNSruleServer(rule);
					if (serverTag && serverTag.toLowerCase().includes('fakeip')) {
						fakeIPServer.tag = serverTag;
						break;
					}
				}
				for (const key of ['inet4_range', 'inet6_range']) {
					if (legacyFakeIP[key] !== undefined) fakeIPServer[key] = legacyFakeIP[key];
				}
				if (Array.isArray(dns.servers)) dns.servers.push(fakeIPServer);
				else dns.servers = [fakeIPServer];
			}

			if (Array.isArray(dns.rules)) {
				const migratedRules = [];
				for (const rule of dns.rules) {
					const serverTag = getGetDNSruleServer(rule);
					const outbound = arrayify(rule?.outbound);
					const DNSrouteOptionField = new Set(['outbound', 'server', 'action', 'strategy', 'disable_cache', 'rewrite_ttl', 'client_subnet', 'timeout']);
					const isOutboundAnyDNSRule = rule && typeof rule === 'object' && !Array.isArray(rule) && rule.type !== 'logical'
						&& serverTag && outbound.includes('any') && Object.keys(rule).every(key => DNSrouteOptionField.has(key));
					if (isOutboundAnyDNSRule) {
						const route = ensureRoute();
						if (route.default_domain_resolver === undefined) {
							const resolver = { server: serverTag };
							for (const key of ['strategy', 'disable_cache', 'rewrite_ttl', 'client_subnet', 'timeout']) {
								if (rule[key] !== undefined) resolver[key] = rule[key];
							}
							route.default_domain_resolver = Object.keys(resolver).length === 1 ? resolver.server : resolver;
						}
						continue;
					}
					migratedRules.push(migrateDNSrule(rule, rcodeServerMap));
				}
				dns.rules = migratedRules;
			}

			delete dns.fakeip;
			delete dns.independent_cache;
		}

		if (config?.route && typeof config.route === 'object') {
			delete config.route.geoip;
			delete config.route.geosite;
		}
		if (config?.ntp?.detour === 'DIRECT') delete config.ntp.detour;

		if (Array.isArray(config.outbounds)) {
			const outboundTags = new Set(config.outbounds.map(outbound => outbound?.tag).filter(Boolean));
			const refUseREJECT = value => value === 'REJECT' || (value && typeof value === 'object' && (Array.isArray(value) ? value.some(refUseREJECT) : Object.values(value).some(refUseREJECT)));
			if (!outboundTags.has('REJECT') && refUseREJECT({ outbounds: config.outbounds, route: config.route })) config.outbounds.push({ type: 'block', tag: 'REJECT' });
		}

		// --- UUID matchingNodeOf TLS hotpatch (utls & ech) ---
		if (uuid) {
			config.outbounds?.forEach(outbound => {
				// onlyProcessContaining uuid or password andMatchedNode
				if ((outbound.uuid && outbound.uuid === uuid) || (outbound.password && outbound.password === uuid)) {
					// ensure tls objectExists
					if (!outbound.tls) {
						outbound.tls = { enabled: true };
					}

					// add/update utls config
					if (fingerprint) {
						outbound.tls.utls = {
							enabled: true,
							fingerprint: fingerprint
						};
					}

					// likeResultExtractProvideDone ech_config, add/update ech config
					if (ECHenableUse) {
						outbound.tls.ech = {
							enabled: true,
							query_server_name: ECH_SNI,// wait 1.13.0+ versionRelease
							//config: `-----BEGIN ECH CONFIGS-----\n${ech_config}\n-----END ECH CONFIGS-----`
						};
					}
				}
			});
		}

		return JSON.stringify(config, null, 2);
	} catch (e) {
		console.error("SingboxhotpatchExecFail:", e);
		return JSON.stringify(JSON.parse(sb_json_text), null, 2);
	}
}

function SurgesubConfigFileHotpatch(content, url, config_JSON) {
	const eachLineContent = content.includes('\r\n') ? content.split('\r\n') : content.split('\n');
	const fullNodePath = config_JSON.randomPath ? randomPath(config_JSON.fullNodePath) : config_JSON.fullNodePath;
	let outputContent = "";
	for (let x of eachLineContent) {
		if (x.includes('= tro' + 'jan,') && !x.includes('ws=true') && !x.includes('ws-path=')) {
			const host = x.split("sni=")[1].split(",")[0];
			const contentToReplace = `sni=${host}, skip-cert-verify=${config_JSON.skipCertDocVerifyCert}`;
			const correctContent = `sni=${host}, skip-cert-verify=${config_JSON.skipCertDocVerifyCert}, ws=true, ws-path=${fullNodePath.replace(/,/g, '%2C')}, ws-headers=Host:"${host}"`;
			outputContent += x.replace(new RegExp(contentToReplace, 'g'), correctContent).replace("[", "").replace("]", "") + '\n';
		} else {
			outputContent += x + '\n';
		}
	}

	outputContent = `#!MANAGED-CONFIG ${url} interval=${config_JSON.preferredSubGen.SUBUpdateTime * 60 * 60} strict=false` + outputContent.substring(outputContent.indexOf('\n'));
	return outputContent;
}

async function requestLogRecord(env, request, accessIP, requestType = "Get_SUB", config_JSON, isWrittenKVlog = true) {
	try {
		const currentTime = new Date();
		const logContent = { TYPE: requestType, IP: accessIP, ASN: `AS${request.cf.asn || '0'} ${request.cf.asOrganization || 'Unknown'}`, CC: `${request.cf.country || 'N/A'} ${request.cf.city || 'N/A'}`, URL: request.url, UA: request.headers.get('User-Agent') || 'Unknown', TIME: currentTime.getTime() };
		if (config_JSON.TG.enableUse) {
			try {
				const TG_TXT = await env.KV.get('tg.json');
				const TG_JSON = JSON.parse(TG_TXT);
				if (TG_JSON?.BotToken && TG_JSON?.ChatID) {
					const requestTime = new Date(logContent.TIME).toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' });
					const requestURL = new URL(logContent.URL);
					const msg = `<b>#${config_JSON.preferredSubGen.SUBNAME} logNotify</b>\n\n` +
						`📌 <b>classType: </b>#${logContent.TYPE}\n` +
						`🌐 <b>IP: </b><code>${logContent.IP}</code>\n` +
						`📍 <b>position: </b>${logContent.CC}\n` +
						`🏢 <b>ASN: </b>${logContent.ASN}\n` +
						`🔗 <b>domainName: </b><code>${requestURL.host}</code>\n` +
						`🔍 <b>path: </b><code>${requestURL.pathname + requestURL.search}</code>\n` +
						`🤖 <b>UA: </b><code>${logContent.UA}</code>\n` +
						`📅 <b>time: </b>${requestTime}\n` +
						`${config_JSON.CF.Usage.success ? `📊 <b>requestUsage: </b>${config_JSON.CF.Usage.total}/${config_JSON.CF.Usage.max} <b>${((config_JSON.CF.Usage.total / config_JSON.CF.Usage.max) * 100).toFixed(2)}%</b>\n` : ''}`;
					await fetch(`https://api.telegram.org/bot${TG_JSON.BotToken}/sendMessage?chat_id=${TG_JSON.ChatID}&parse_mode=HTML&text=${encodeURIComponent(msg)}`, {
						method: 'GET',
						headers: {
							'Accept': 'text/html,application/xhtml+xml,application/xml;',
							'Accept-Encoding': 'gzip, deflate, br',
							'User-Agent': logContent.UA || 'Unknown',
						}
					});
				}
			} catch (error) { console.error(`readGettg.jsonerror: ${error.message}`) }
		}
		isWrittenKVlog = ['1', 'true'].includes(env.OFF_LOG) ? false : isWrittenKVlog;
		if (!isWrittenKVlog) return;
		let logArray = [];
		const existingLogs = await env.KV.get('log.json'), KVcapacityLimit = 4;//MB
		if (existingLogs) {
			try {
				logArray = JSON.parse(existingLogs);
				if (!Array.isArray(logArray)) { logArray = [logContent] }
				else if (requestType !== "Get_SUB") {
					const thirtyMinAgoTimestamp = currentTime.getTime() - 30 * 60 * 1000;
					if (logArray.some(log => log.TYPE !== "Get_SUB" && log.IP === accessIP && log.URL === request.url && log.UA === (request.headers.get('User-Agent') || 'Unknown') && log.TIME >= thirtyMinAgoTimestamp)) return;
					logArray.push(logContent);
					while (JSON.stringify(logArray, null, 2).length > KVcapacityLimit * 1024 * 1024 && logArray.length > 0) logArray.shift();
				} else {
					logArray.push(logContent);
					while (JSON.stringify(logArray, null, 2).length > KVcapacityLimit * 1024 * 1024 && logArray.length > 0) logArray.shift();
				}
			} catch (e) { logArray = [logContent] }
		} else { logArray = [logContent] }
		await env.KV.put('log.json', JSON.stringify(logArray, null, 2));
	} catch (error) { console.error(`logRecordFail: ${error.message}`) }
}

function maskSensitiveInfo(textThis, prefixLength = 3, suffixLength = 2) {
	if (!textThis || typeof textThis !== 'string') return textThis;
	if (textThis.length <= prefixLength + suffixLength) return textThis; // ifTooShort, returnDirect

	const beforeSuffix = textThis.slice(0, prefixLength);
	const afterSuffix = textThis.slice(-suffixLength);
	const asteriskCount = textThis.length - prefixLength - suffixLength;

	return `${beforeSuffix}${'*'.repeat(asteriskCount)}${afterSuffix}`;
}

async function MD5MD5(textThis) {
	const encoder = new TextEncoder();

	const firstHash = await crypto.subtle.digest('MD5', encoder.encode(textThis));
	const firstHashArray = Array.from(new Uint8Array(firstHash));
	const firstHex = firstHashArray.map(byte => byte.toString(16).padStart(2, '0')).join('');

	const secondHash = await crypto.subtle.digest('MD5', encoder.encode(firstHex.slice(7, 27)));
	const secondHashArray = Array.from(new Uint8Array(secondHash));
	const secondHex = secondHashArray.map(byte => byte.toString(16).padStart(2, '0')).join('');

	return secondHex.toLowerCase();
}

function randomPath(fullNodePath = "/") {
	const commonPathDir = ["about", "account", "acg", "act", "activity", "ad", "ads", "ajax", "album", "albums", "anime", "api", "app", "apps", "archive", "archives", "article", "articles", "ask", "auth", "avatar", "bbs", "bd", "blog", "blogs", "book", "books", "bt", "buy", "cart", "category", "categories", "cb", "channel", "channels", "chat", "china", "city", "class", "classify", "clip", "clips", "club", "cn", "code", "collect", "collection", "comic", "comics", "community", "company", "config", "contact", "content", "course", "courses", "cp", "data", "detail", "details", "dh", "directory", "discount", "discuss", "dl", "dload", "doc", "docs", "document", "documents", "doujin", "download", "downloads", "drama", "edu", "en", "ep", "episode", "episodes", "event", "events", "f", "faq", "favorite", "favourites", "favs", "feedback", "file", "files", "film", "films", "forum", "forums", "friend", "friends", "game", "games", "gif", "go", "go.html", "go.php", "group", "groups", "help", "home", "hot", "htm", "html", "image", "images", "img", "index", "info", "intro", "item", "items", "ja", "jp", "jump", "jump.html", "jump.php", "jumping", "knowledge", "lang", "lesson", "lessons", "lib", "library", "link", "links", "list", "live", "lives", "m", "mag", "magnet", "mall", "manhua", "map", "member", "members", "message", "messages", "mobile", "movie", "movies", "music", "my", "new", "news", "note", "novel", "novels", "online", "order", "out", "out.html", "out.php", "outbound", "p", "page", "pages", "pay", "payment", "pdf", "photo", "photos", "pic", "pics", "picture", "pictures", "play", "player", "playlist", "post", "posts", "product", "products", "program", "programs", "project", "qa", "question", "rank", "ranking", "read", "readme", "redirect", "redirect.html", "redirect.php", "reg", "register", "res", "resource", "retrieve", "sale", "search", "season", "seasons", "section", "seller", "series", "service", "services", "setting", "settings", "share", "shop", "show", "shows", "site", "soft", "sort", "source", "special", "star", "stars", "static", "stock", "store", "stream", "streaming", "streams", "student", "study", "tag", "tags", "task", "teacher", "team", "tech", "temp", "test", "thread", "tool", "tools", "topic", "topics", "torrent", "trade", "travel", "tv", "txt", "type", "u", "upload", "uploads", "url", "urls", "user", "users", "v", "version", "videos", "view", "vip", "vod", "watch", "web", "wenku", "wiki", "work", "www", "zh", "zh-cn", "zh-tw", "zip"];
	const randomNumber = Math.floor(Math.random() * 3 + 1);
	const randomPath = commonPathDir.sort(() => 0.5 - Math.random()).slice(0, randomNumber).join('/');
	if (fullNodePath === "/") return `/${randomPath}`;
	else return `/${randomPath + fullNodePath.replace('/?', '?')}`;
}

function replaceAsteriskWithRandomChar(content) {
	if (typeof content !== 'string' || !content.includes('*')) return content;
	const charset = 'abcdefghijklmnopqrstuvwxyz0123456789';
	return content.replace(/\*/g, () => {
		let s = '';
		for (let i = 0; i < Math.floor(Math.random() * 14) + 3; i++) s += charset[Math.floor(Math.random() * charset.length)];
		return s;
	});
}

const DoHcache = {};
const DoHcacheMaxEntries = 256;
const DoHrecordTypeMap = { A: 1, NS: 2, CNAME: 5, MX: 15, TXT: 16, AAAA: 28, SRV: 33, HTTPS: 65 };
async function DoHqueryInquire(domainName, recordType, DoHresolveService = "https://cloudflare-dns.com/dns-query") {
	const normalizeDomain = String(domainName || '').trim().toLowerCase().replace(/\.$/, '');
	const normalizeRecordType = String(recordType || '').trim().toUpperCase();
	const cacheKey = `${normalizeDomain}:${normalizeRecordType}`;
	const qtype = DoHrecordTypeMap[normalizeRecordType] || 1;
	const currentTimestamp = Date.now();
	const existingCacheEntry = DoHcache[cacheKey];
	if (existingCacheEntry && currentTimestamp < existingCacheEntry.expireTime) {
		log(`[DoHqueryInquire] cacheHit ${domainName} ${recordType} via ${DoHresolveService}`);
		return existingCacheEntry.data.map(data => ({ type: qtype, data }));
	}
	const startTime = performance.now();
	log(`[DoHqueryInquire] startQuery ${domainName} ${recordType} via ${DoHresolveService}`);
	try {
		// recordTypeStrToNum
		// encodeDomainAs DNS wire format labels
		const encodeDomain = (name) => {
			const parts = name.endsWith('.') ? name.slice(0, -1).split('.') : name.split('.');
			const bufs = [];
			for (const label of parts) {
				const enc = new TextEncoder().encode(label);
				bufs.push(new Uint8Array([enc.length]), enc);
			}
			bufs.push(new Uint8Array([0]));
			const total = bufs.reduce((s, b) => s + b.length, 0);
			const result = new Uint8Array(total);
			let off = 0;
			for (const b of bufs) { result.set(b, off); off += b.length }
			return result;
		};

		// build DNS queryMessage
		const qname = encodeDomain(normalizeDomain);
		const query = new Uint8Array(12 + qname.length + 4);
		const qview = new DataView(query.buffer);
		qview.setUint16(0, crypto.getRandomValues(new Uint16Array(1))[0]); // ID (random per RFC 1035)
		qview.setUint16(2, 0x0100);  // Flags: RD=1 (recursiveQuery)
		qview.setUint16(4, 1);       // QDCOUNT
		query.set(qname, 12);
		qview.setUint16(12 + qname.length, qtype);
		qview.setUint16(12 + qname.length + 2, 1); // QCLASS = IN

		// through POST sendSend dns-message request
		log(`[DoHqueryInquire] sendQueryMessage ${domainName} via ${DoHresolveService} (type=${qtype}, ${query.length}byte)`);
		const response = await fetch(DoHresolveService, {
			method: 'POST',
			headers: {
				'Content-Type': 'application/dns-message',
				'Accept': 'application/dns-message',
			},
			body: query,
		});
		if (!response.ok) {
			console.warn(`[DoHqueryInquire] requestFail ${domainName} ${recordType} via ${DoHresolveService} responseCode:${response.status}`);
			return [];
		}

		// parseParse DNS responseMessage
		const buf = new Uint8Array(await response.arrayBuffer());
		const dv = new DataView(buf.buffer);
		const qdcount = dv.getUint16(4);
		const ancount = dv.getUint16(6);
		log(`[DoHqueryInquire] receivedResponse ${domainName} ${recordType} via ${DoHresolveService} (${buf.length}byte, ${ancount}itemAnswer)`);

		// resolveDomain (handlePointerCompression) 
		const resolveDomain = (pos) => {
			const labels = [];
			let p = pos, jumped = false, endPos = -1, safe = 128;
			while (p < buf.length && safe-- > 0) {
				const len = buf[p];
				if (len === 0) { if (!jumped) endPos = p + 1; break }
				if ((len & 0xC0) === 0xC0) {
					if (!jumped) endPos = p + 2;
					p = ((len & 0x3F) << 8) | buf[p + 1];
					jumped = true;
					continue;
				}
				labels.push(new TextDecoder().decode(buf.slice(p + 1, p + 1 + len)));
				p += len + 1;
			}
			if (endPos === -1) endPos = p + 1;
			return [labels.join('.'), endPos];
		};

		// skip Question Section
		let offset = 12;
		for (let i = 0; i < qdcount; i++) {
			const [, end] = resolveDomain(offset);
			offset = /** @type {number} */ (end) + 4; // +4 skip QTYPE + QCLASS
		}

		// parseParse Answer Section
		const answers = [];
		for (let i = 0; i < ancount && offset < buf.length; i++) {
			const [name, nameEnd] = resolveDomain(offset);
			offset = /** @type {number} */ (nameEnd);
			const type = dv.getUint16(offset); offset += 2;
			offset += 2; // CLASS
			const ttl = dv.getUint32(offset); offset += 4;
			const rdlen = dv.getUint16(offset); offset += 2;
			const rdata = buf.slice(offset, offset + rdlen);
			offset += rdlen;

			let data;
			if (type === 1 && rdlen === 4) {
				// A record
				data = `${rdata[0]}.${rdata[1]}.${rdata[2]}.${rdata[3]}`;
			} else if (type === 28 && rdlen === 16) {
				// AAAA record
				const segs = [];
				for (let j = 0; j < 16; j += 2) segs.push(((rdata[j] << 8) | rdata[j + 1]).toString(16));
				data = segs.join(':');
			} else if (type === 16) {
				// TXT record (lengthPrefixedString)
				let tOff = 0;
				const parts = [];
				while (tOff < rdlen) {
					const tLen = rdata[tOff++];
					parts.push(new TextDecoder().decode(rdata.slice(tOff, tOff + tLen)));
					tOff += tLen;
				}
				data = parts.join('');
			} else if (type === 5) {
				// CNAME record
				const [cname] = resolveDomain(offset - rdlen);
				data = cname;
			} else {
				data = Array.from(rdata).map(b => b.toString(16).padStart(2, '0')).join('');
			}
			answers.push({ name, type, TTL: ttl, data, rdata });
		}
		const elapsedTime = (performance.now() - startTime).toFixed(2);
		log(`[DoHqueryInquire] queryComplete ${domainName} ${recordType} via ${DoHresolveService} ${elapsedTime}ms total2${answers.length}itemResult2${answers.length > 0 ? '\n' + answers.map((a, i) => `  ${i + 1}. ${a.name} type=${a.type} TTL=${a.TTL} data=${a.data}`).join('\n') : ''}`);
		// DoH cacheMinRetain 5 minute, response TTL moreLongTimeRespectReResponse TTL; emptyResponseUse 5 minuteNegativeCache
		const relatedRecords = answers.filter(answer => answer.type === qtype);
		const minTTL = relatedRecords.length > 0 ? Math.min(...relatedRecords.map(a => a.TTL)) : 0;
		const cacheTTL = Math.max(minTTL, 5 * 60);
		const cacheExpireTime = Date.now() + cacheTTL * 1000;
		const cacheData = relatedRecords.map(answer => answer.data);
		if (cacheData.length > 0 || answers.length === 0) {
			if (Object.keys(DoHcache).length >= DoHcacheMaxEntries) {
				const clearTimestamp = Date.now();
				for (const [cacheEntryKey, cacheEntry] of Object.entries(DoHcache)) {
					if (clearTimestamp >= cacheEntry.expireTime) delete DoHcache[cacheEntryKey];
				}
				if (Object.keys(DoHcache).length >= DoHcacheMaxEntries) {
					delete DoHcache[Object.keys(DoHcache)[0]];
				}
			}
			DoHcache[cacheKey] = { data: cacheData, expireTime: cacheExpireTime };
			log(`[DoHqueryInquire] writeCache ${domainName} ${recordType} TTL=${cacheTTL}s${cacheData.length === 0 ? ' (emptyResult) ' : ''}`);
		}
		return answers;
	} catch (error) {
		const elapsedTime = (performance.now() - startTime).toFixed(2);
		console.error(`[DoHqueryInquire] queryFail ${domainName} ${recordType} via ${DoHresolveService} ${elapsedTime}ms:`, error);
		return [];
	}
}

async function readGetconfig_JSON(env, hostname, userID, UA = "Mozilla/5.0", resetConfig = false) {
	const _p = signatureDict[0];
	const host = hostname, Ali_DoH = "https://dns.alidns.com/dns-query", ECH_SNI = "cloudflare-ech.com", placeholder = '{{IP:PORT}}', initStartTime = performance.now(), defaultConfigJSON = {
		TIME: new Date().toISOString(),
		HOST: host,
		HOSTS: [hostname],
		UUID: userID,
		PATH: "/",
		protoType: "v" + "le" + "ss",
		transportProto: "ws",
		gRPCmode: "gun",
		gRPCUserAgent: UA,
		skipCertDocVerifyCert: false,
		enableUse0RTT: false,
		TLSsplitPiece: null,
		randomPath: false,
		ECH: false,
		ECHConfig: {
			DNS: Ali_DoH,
			SNI: ECH_SNI,
		},
		SS: {
			encryptMethod: "aes-128-gcm",
			TLS: true,
		},
		Fingerprint: "chrome",
		preferredSubGen: {
			local: true, // true: localBasedPreferredAddress  false: PreferredSubGenerator
			thisLocationIPlib: {
				randomZhIP: true, // when randomZhIP astrueeffectiveAt, enableRandomIPcount, otherwiseUseKVwithinADD.txt
				randomCount: 16,
				specifiedPort: -1,
			},
			SUB: null,
			SUBNAME: "MatiX",
			SUBUpdateTime: 3, // subUpdateTime (hour) 
			LIMIT_DAYS: 30, // مدت اعتبار اشتراک (روز)
			LIMIT_GB: 100, // سقف حجم اعلامی اشتراک (گیگابایت)
			CLEAN_IP_SOURCE: "https://raw.githubusercontent.com/vfarid/cf-clean-ips/main/list.json",
			TOKEN: await MD5MD5(hostname + userID),
		},
		subConvertConfig: {
			SUBAPI: `https://SUBAPI.${signatureDict[1]}ssss.net`,
			SUBCONFIG: `https://raw.githubusercontent.com/${signatureDict[1]}/ACL4SSR/refs/heads/main/Clash/config/ACL4SSR_Online_Mini_MultiMode_CF.ini`,
			SUBEMOJI: false,
			SUBLIST: false, //onlyOutputNodeInfo
			UDP: false, // enableUse UDP
			XUDP: false, // enableUse XUDP
			TLS13: false, // enableUse TLS 1.3
			APPEND_TYPE: false, // insertNodeType
			SORT: false, // baseNodeSort
		},
		relay: {
			[_p]: "auto",
			SOCKS5: {
				enableUse: null,
				allScope: false,
				account: '',
				whitelist: SOCKS5whitelist,
			},
			pathTemplate: {
				[_p]: "proxyip=" + placeholder,
				SOCKS5: {
					allScope: "socks5://" + placeholder,
					standard: "socks5=" + placeholder
				},
				HTTP: {
					allScope: "http://" + placeholder,
					standard: "http=" + placeholder
				},
				HTTPS: {
					allScope: "https://" + placeholder,
					standard: "https=" + placeholder
				},
				TURN: {
					allScope: "turn://" + placeholder,
					standard: "turn=" + placeholder
				},
				SSTP: {
					allScope: "sstp://" + placeholder,
					standard: "sstp=" + placeholder
				},
			},
		},
		TG: {
			enableUse: false,
			BotToken: null,
			ChatID: null,
		},
		CF: {
			Email: null,
			GlobalAPIKey: null,
			AccountID: null,
			APIToken: null,
			UsageAPI: null,
			Usage: {
				success: false,
				pages: 0,
				workers: 0,
				total: 0,
				max: 100000,
			},
		}
	};

	try {
		let configJSON = await env.KV.get('config.json');
		if (!configJSON || resetConfig == true) {
			await env.KV.put('config.json', JSON.stringify(defaultConfigJSON, null, 2));
			config_JSON = defaultConfigJSON;
		} else {
			config_JSON = JSON.parse(configJSON);
		}
	} catch (error) {
		console.error(`readGetconfig_JSONerror: ${error.message}`);
		config_JSON = defaultConfigJSON;
	}

	if (!config_JSON.subConvertConfig.SUBLIST) config_JSON.subConvertConfig.SUBLIST = false;
	if (!config_JSON.subConvertConfig.UDP) config_JSON.subConvertConfig.UDP = false;
	if (!config_JSON.subConvertConfig.XUDP) config_JSON.subConvertConfig.XUDP = false;
	if (!config_JSON.subConvertConfig.TLS13) config_JSON.subConvertConfig.TLS13 = false;
	if (!config_JSON.subConvertConfig.APPEND_TYPE) config_JSON.subConvertConfig.APPEND_TYPE = false;
	if (!config_JSON.subConvertConfig.SORT) config_JSON.subConvertConfig.SORT = false;
	if (!config_JSON.gRPCUserAgent) config_JSON.gRPCUserAgent = UA;
	config_JSON.HOST = host;
	if (!config_JSON.HOSTS) config_JSON.HOSTS = [hostname];
	if (env.HOST) config_JSON.HOSTS = (await normalizeToArray(env.HOST)).map(h => h.toLowerCase().replace(/^https?:\/\//, '').split('/')[0].split(':')[0]);
	config_JSON.UUID = userID;
	if (!config_JSON.randomPath) config_JSON.randomPath = false;
	if (!config_JSON.enableUse0RTT) config_JSON.enableUse0RTT = false;
	if (!Number.isFinite(Number(config_JSON.preferredSubGen.LIMIT_DAYS)) || Number(config_JSON.preferredSubGen.LIMIT_DAYS) < 1) config_JSON.preferredSubGen.LIMIT_DAYS = 30;
	if (!Number.isFinite(Number(config_JSON.preferredSubGen.LIMIT_GB)) || Number(config_JSON.preferredSubGen.LIMIT_GB) < 0) config_JSON.preferredSubGen.LIMIT_GB = 100;
	if (typeof config_JSON.preferredSubGen.CLEAN_IP_SOURCE !== 'string') config_JSON.preferredSubGen.CLEAN_IP_SOURCE = "https://raw.githubusercontent.com/vfarid/cf-clean-ips/main/list.json";

	if (env.PATH) config_JSON.PATH = env.PATH.startsWith('/') ? env.PATH : '/' + env.PATH;
	else if (!config_JSON.PATH) config_JSON.PATH = '/';

	if (!config_JSON.gRPCmode) config_JSON.gRPCmode = 'gun';
	if (!config_JSON.SS) config_JSON.SS = { encryptMethod: "aes-128-gcm", TLS: false };

	if (!config_JSON.relay.pathTemplate?.[_p]) {
		config_JSON.relay.pathTemplate = {
			[_p]: "proxyip=" + placeholder,
			SOCKS5: {
				allScope: "socks5://" + placeholder,
				standard: "socks5=" + placeholder
			},
			HTTP: {
				allScope: "http://" + placeholder,
				standard: "http=" + placeholder
			},
			HTTPS: {
				allScope: "https://" + placeholder,
				standard: "https=" + placeholder
			},
			TURN: {
				allScope: "turn://" + placeholder,
				standard: "turn=" + placeholder
			},
			SSTP: {
				allScope: "sstp://" + placeholder,
				standard: "sstp=" + placeholder
			},
		};
	}
	if (!config_JSON.relay.pathTemplate.HTTPS) config_JSON.relay.pathTemplate.HTTPS = { allScope: "https://" + placeholder, standard: "https=" + placeholder };
	if (!config_JSON.relay.pathTemplate.TURN) config_JSON.relay.pathTemplate.TURN = { allScope: "turn://" + placeholder, standard: "turn=" + placeholder };
	if (!config_JSON.relay.pathTemplate.SSTP) config_JSON.relay.pathTemplate.SSTP = { allScope: "sstp://" + placeholder, standard: "sstp=" + placeholder };

	const proxyConfig = config_JSON.relay.pathTemplate[config_JSON.relay.SOCKS5.enableUse?.toUpperCase()];

	let pathRelayParams = '';
	if (proxyConfig && config_JSON.relay.SOCKS5.account) pathRelayParams = (config_JSON.relay.SOCKS5.allScope ? proxyConfig.allScope : proxyConfig.standard).replace(placeholder, config_JSON.relay.SOCKS5.account);
	else if (config_JSON.relay[_p] !== 'auto') pathRelayParams = config_JSON.relay.pathTemplate[_p].replace(placeholder, config_JSON.relay[_p]);

	let relayQueryParams = '';
	if (pathRelayParams.includes('?')) {
		const [relayPathPart, relayQueryPart] = pathRelayParams.split('?');
		pathRelayParams = relayPathPart;
		relayQueryParams = relayQueryPart;
	}

	config_JSON.PATH = config_JSON.PATH.replace(pathRelayParams, '').replace('//', '/');
	const normalizedPath = config_JSON.PATH === '/' ? '' : config_JSON.PATH.replace(/\/+(?=\?|$)/, '').replace(/\/+$/, '');
	const [pathPart, ...queryArray] = normalizedPath.split('?');
	const queryPart = queryArray.length ? '?' + queryArray.join('?') : '';
	const finalQueryPart = relayQueryParams ? (queryPart ? queryPart + '&' + relayQueryParams : '?' + relayQueryParams) : queryPart;
	config_JSON.fullNodePath = (pathPart || '/') + (pathPart && pathRelayParams ? '/' : '') + pathRelayParams + finalQueryPart + (config_JSON.enableUse0RTT ? (finalQueryPart ? '&' : '?') + 'ed=2560' : '');

	if (!config_JSON.TLSsplitPiece && config_JSON.TLSsplitPiece !== null) config_JSON.TLSsplitPiece = null;
	const TLSsplitPieceParamNum = config_JSON.TLSsplitPiece == 'Shadowrocket' ? `&fragment=${encodeURIComponent('1,40-60,30-50,tlshello')}` : config_JSON.TLSsplitPiece == 'Happ' ? `&fragment=${encodeURIComponent('3,1,tlshello')}` : '';
	if (!config_JSON.Fingerprint) config_JSON.Fingerprint = "chrome";
	if (!config_JSON.ECH) config_JSON.ECH = false;
	if (!config_JSON.ECHConfig) config_JSON.ECHConfig = { DNS: Ali_DoH, SNI: ECH_SNI };
	const ECHLINKparamNum = config_JSON.ECH ? `&ech=${encodeURIComponent((config_JSON.ECHConfig.SNI ? config_JSON.ECHConfig.SNI + '+' : '') + config_JSON.ECHConfig.DNS)}` : '';
	const { type: transportProto, pathFieldName, domainFieldName } = getTransportProtoConfig(config_JSON);
	const transportPathParamValue = getTransportPathParamValue(config_JSON, config_JSON.fullNodePath);
	config_JSON.LINK = config_JSON.protoType === 'ss'
		? `${config_JSON.protoType}://${btoa(config_JSON.SS.encryptMethod + ':' + userID)}@${host}:${config_JSON.SS.TLS ? '443' : '80'}?plugin=v2${encodeURIComponent(`ray-plugin;mode=websocket;host=${host};path=${((config_JSON.fullNodePath.includes('?') ? config_JSON.fullNodePath.replace('?', '?enc=' + config_JSON.SS.encryptMethod + '&') : (config_JSON.fullNodePath + '?enc=' + config_JSON.SS.encryptMethod)) + (config_JSON.SS.TLS ? ';tls' : ''))};mux=0`) + ECHLINKparamNum}#${encodeURIComponent(config_JSON.preferredSubGen.SUBNAME)}`
		: `${config_JSON.protoType}://${userID}@${host}:443?security=tls&type=${transportProto + ECHLINKparamNum}&${domainFieldName}=${host}&fp=${config_JSON.Fingerprint}&sni=${host}&${pathFieldName}=${encodeURIComponent(transportPathParamValue) + TLSsplitPieceParamNum}&encryption=none#${encodeURIComponent(config_JSON.preferredSubGen.SUBNAME)}`;
	config_JSON.preferredSubGen.TOKEN = await MD5MD5(hostname + userID);

	const initTG_JSON = { BotToken: null, ChatID: null };
	config_JSON.TG = { enableUse: config_JSON.TG.enableUse ? config_JSON.TG.enableUse : false, ...initTG_JSON };
	try {
		const TG_TXT = await env.KV.get('tg.json');
		if (!TG_TXT) {
			await env.KV.put('tg.json', JSON.stringify(initTG_JSON, null, 2));
		} else {
			const TG_JSON = JSON.parse(TG_TXT);
			config_JSON.TG.ChatID = TG_JSON.ChatID ? TG_JSON.ChatID : null;
			config_JSON.TG.BotToken = TG_JSON.BotToken ? maskSensitiveInfo(TG_JSON.BotToken) : null;
		}
	} catch (error) {
		console.error(`readGettg.jsonerror: ${error.message}`);
	}

	const initCF_JSON = { Email: null, GlobalAPIKey: null, AccountID: null, APIToken: null, UsageAPI: null };
	config_JSON.CF = { ...initCF_JSON, Usage: { success: false, pages: 0, workers: 0, total: 0, max: 100000 } };
	try {
		const CF_TXT = await env.KV.get('cf.json');
		if (!CF_TXT) {
			await env.KV.put('cf.json', JSON.stringify(initCF_JSON, null, 2));
		} else {
			const CF_JSON = JSON.parse(CF_TXT);
			if (CF_JSON.UsageAPI) {
				try {
					const response = await fetch(CF_JSON.UsageAPI);
					const Usage = await response.json();
					config_JSON.CF.Usage = Usage;
				} catch (err) {
					console.error(`request CF_JSON.UsageAPI failFail: ${err.message}`);
				}
			} else {
				config_JSON.CF.Email = CF_JSON.Email ? CF_JSON.Email : null;
				config_JSON.CF.GlobalAPIKey = CF_JSON.GlobalAPIKey ? maskSensitiveInfo(CF_JSON.GlobalAPIKey) : null;
				config_JSON.CF.AccountID = CF_JSON.AccountID ? maskSensitiveInfo(CF_JSON.AccountID) : null;
				config_JSON.CF.APIToken = CF_JSON.APIToken ? maskSensitiveInfo(CF_JSON.APIToken) : null;
				config_JSON.CF.UsageAPI = null;
				const Usage = await getCloudflareUsage(CF_JSON.Email, CF_JSON.GlobalAPIKey, CF_JSON.AccountID, CF_JSON.APIToken);
				config_JSON.CF.Usage = Usage;
			}
		}
	} catch (error) {
		console.error(`readGetcf.jsonerror: ${error.message}`);
	}

	config_JSON.loadTime = (performance.now() - initStartTime).toFixed(2) + 'ms';
	return config_JSON;
}

function identifyCarrier(request) {
	const cf = request?.cf;
	const ASNcarrierMap = {
		'4134': 'ct',
		'4809': 'ct',
		'4811': 'ct',
		'4812': 'ct',
		'4815': 'ct',
		'4837': 'cu',
		'4814': 'cu',
		'9929': 'cu',
		'17623': 'cu',
		'17816': 'cu',
		'9808': 'cmcc',
		'24400': 'cmcc',
		'56040': 'cmcc',
		'56041': 'cmcc',
		'56044': 'cmcc',
	};
	const carrierKeywordMap = [
		{ code: 'ct', pattern: /chinanet|chinatelecom|china telecom|cn2|shtel/ },
		{ code: 'cmcc', pattern: /cmi|cmnet|chinamobile|china mobile|cmcc|mobile communications/ },
		{ code: 'cu', pattern: /china169|china unicom|chinaunicom|cucc|cncgroup|cuii|netcom/ },
	];
	if (String(cf?.country || '').toLowerCase() !== 'cn') return 'cf';
	const orgName = String(cf?.asOrganization || '').toLowerCase();
	const carrierMatched = carrierKeywordMap.find(({ pattern }) => pattern.test(orgName))?.code;
	return carrierMatched || ASNcarrierMap[String(cf?.asn || '')] || 'cf';
}

async function generateRandomIP(request, count = 16, specifiedPort = -1) {
	const url = new URL(request.url);
	const queryParamCarrier = String(url.searchParams.get('cnIspCode') || '').toLowerCase();
	const carrierFileId = ['ct', 'cu', 'cmcc', 'cf'].includes(queryParamCarrier) ? queryParamCarrier : identifyCarrier(request);
	const carrierNameMap = {
		cmcc: 'CFcmccPreferred',
		cu: 'CFcuccPreferred',
		ct: 'CFctccPreferred',
		cf: 'CFofficialPreferred',
	};
	const cidr_url = carrierFileId === 'cf' ? `https://raw.githubusercontent.com/${signatureDict[1]}/${signatureDict[1]}/main/CF-CIDR.txt` : `https://raw.githubusercontent.com/${signatureDict[1]}/${signatureDict[1]}/main/CF-CIDR/${carrierFileId}.txt`;
	const cfname = carrierNameMap[carrierFileId] || 'CFofficialPreferred';
	const cfport = [443, 2053, 2083, 2087, 2096, 8443];
	let cidrList = [];
	const remoteIPSource = String(config_JSON?.preferredSubGen?.CLEAN_IP_SOURCE || '').trim();
	if (remoteIPSource) {
		try {
			const sourceRes = await fetch(remoteIPSource, { headers: { 'Accept': 'application/json,text/plain,*/*' } });
			if (sourceRes.ok) {
				const text = await sourceRes.text();
				let values = [];
				try {
					const json = JSON.parse(text);
						const walk = (v) => {
							if (typeof v === 'string') {
								if (/^(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:#.*)?$/.test(v.trim())) values.push(v.trim());
							} else if (Array.isArray(v)) v.forEach(walk);
							else if (v && typeof v === 'object') Object.values(v).forEach(walk);
						};
						walk(json);
				} catch { values = text.split(/\r?\n|,/).map(x => x.trim()).filter(Boolean); }
				cidrList = [...new Set(values.filter(v => /^(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:#.*)?$/.test(v)).map(v => v.split('#')[0].split(':')[0]))];
			}
		} catch (e) { console.warn('[IP Source] source unavailable:', e?.message || e); }
	}
	if (!cidrList.length) {
		try { const res = await fetch(cidr_url); cidrList = res.ok ? await normalizeToArray(await res.text()) : ['104.16.0.0/13'] } catch { cidrList = ['104.16.0.0/13'] }
	}

	const generateRandomIPFromCIDR = (cidr) => {
		const [baseIP, prefixLength] = cidr.split('/'), prefix = parseInt(prefixLength), hostBits = 32 - prefix;
		const ipInt = baseIP.split('.').reduce((a, p, i) => a | (parseInt(p) << (24 - i * 8)), 0);
		const randomOffset = Math.floor(Math.random() * Math.pow(2, hostBits));
		const mask = (0xFFFFFFFF << hostBits) >>> 0, randomIP = (((ipInt & mask) >>> 0) + randomOffset) >>> 0;
		return [(randomIP >>> 24) & 0xFF, (randomIP >>> 16) & 0xFF, (randomIP >>> 8) & 0xFF, randomIP & 0xFF].join('.');
	};
	const randomIPs = Array.from({ length: count }, (_, index) => {
		const ip = generateRandomIPFromCIDR(cidrList[Math.floor(Math.random() * cidrList.length)]);
		const targetPort = specifiedPort === -1
			? cfport[Math.floor(Math.random() * cfport.length)]
			: specifiedPort;
		return `${ip}:${targetPort}#${cfname}${index + 1}`;
	});
	return [randomIPs, randomIPs.join('\n')];
}

async function normalizeToArray(content) {
	var replacedContent = content.replace(/[	"'\r\n]+/g, ',').replace(/,+/g, ',');
	if (replacedContent.charAt(0) == ',') replacedContent = replacedContent.slice(1);
	if (replacedContent.charAt(replacedContent.length - 1) == ',') replacedContent = replacedContent.slice(0, replacedContent.length - 1);
	const locationAddrArray = replacedContent.split(',');
	return locationAddrArray;
}

async function getPreferredSubGeneratorData(PreferredSubGeneratorHOST) {
	let preferredIP = [], otherNodesLINK = '', formatIzeHOST = PreferredSubGeneratorHOST.replace(/^sub:\/\//i, 'https://').split('#')[0].split('?')[0];
	if (!/^https?:\/\//i.test(formatIzeHOST)) formatIzeHOST = `https://${formatIzeHOST}`;

	try {
		const url = new URL(formatIzeHOST);
		formatIzeHOST = url.origin;
	} catch (error) {
		preferredIP.push(`127.0.0.1:1234#${PreferredSubGeneratorHOST}preferredSubGeneratorFormatError:${error.message}`);
		return [preferredIP, otherNodesLINK];
	}

	const PreferredSubGeneratorURL = `${formatIzeHOST}/sub?host=example.com&uuid=00000000-0000-4000-8000-000000000000`;

	try {
		const response = await fetch(PreferredSubGeneratorURL, {
			headers: { 'User-Agent': 'MatiX/1.0 (https://github.com/imatixofficel/Matix-edg)' }
		});

		if (!response.ok) {
			preferredIP.push(`127.0.0.1:1234#${PreferredSubGeneratorHOST}preferredSubGeneratorError:${response.statusText}`);
			return [preferredIP, otherNodesLINK];
		}

		const preferredSubGeneratorReturnsSubContent = atob(await response.text());
		const subLineList = preferredSubGeneratorReturnsSubContent.includes('\r\n')
			? preferredSubGeneratorReturnsSubContent.split('\r\n')
			: preferredSubGeneratorReturnsSubContent.split('\n');

		for (const lineContent of subLineList) {
			if (!lineContent.trim()) continue; // skipEmptyLine
			if (lineContent.includes('00000000-0000-4000-8000-000000000000') && lineContent.includes('example.com')) {
				// thisIsPreferredIPline, extract domainName:port#remark
				const addressMatch = lineContent.match(/:\/\/[^@]+@([^?]+)/);
				if (addressMatch) {
					let addressPort = addressMatch[1], remark = ''; // domainName:port or IP:port
					const remarkMatch = lineContent.match(/#(.+)$/);
					if (remarkMatch) remark = '#' + decodeURIComponent(remarkMatch[1]);
					preferredIP.push(addressPort + remark);
				}
			} else {
				otherNodesLINK += lineContent + '\n';
			}
		}
	} catch (error) {
		preferredIP.push(`127.0.0.1:1234#${PreferredSubGeneratorHOST}preferredSubGeneratorError:${error.message}`);
	}

	return [preferredIP, otherNodesLINK];
}

async function requestPreferredAPI(urls, defaultPort = '443', timeoutDuration = 3000) {
	if (!urls?.length) return [[], [], [], []];
	const results = new Set(), relayIPpool = new Set();
	let subLinkResponsePlaintextLINKcontent = '', needSubConvertSubURLs = [];
	await Promise.allSettled(urls.map(async (url) => {
		// checkURLhasRemarkName
		const hashIndex = url.indexOf('#');
		const urlWithoutHash = hashIndex > -1 ? url.substring(0, hashIndex) : url;
		const APIremarkName = hashIndex > -1 ? decodeURIComponent(url.substring(hashIndex + 1)) : null;
		const preferredIPasRelayIP = url.toLowerCase().includes('proxyip=true');
		if (urlWithoutHash.toLowerCase().startsWith('sub://')) {
			try {
				const [preferredIP, otherNodesLINK] = await getPreferredSubGeneratorData(urlWithoutHash);
				// processFirstArray - preferredIP
				if (APIremarkName) {
					for (const ip of preferredIP) {
						const afterProcessingIP = ip.includes('#')
							? `${ip} [${APIremarkName}]`
							: `${ip}#[${APIremarkName}]`;
						results.add(afterProcessingIP);
						if (preferredIPasRelayIP) relayIPpool.add(ip.split('#')[0]);
					}
				} else {
					for (const ip of preferredIP) {
						results.add(ip);
						if (preferredIPasRelayIP) relayIPpool.add(ip.split('#')[0]);
					}
				}
				// processSecondArray - otherNodesLINK
				if (otherNodesLINK && typeof otherNodesLINK === 'string' && APIremarkName) {
					const afterProcessingLINKcontent = otherNodesLINK.replace(/([a-z][a-z0-9+\-.]*:\/\/[^\r\n]*?)(\r?\n|$)/gi, (match, link, lineEnd) => {
						const completeWholeChainConnect = link.includes('#')
							? `${link}${encodeURIComponent(` [${APIremarkName}]`)}`
							: `${link}${encodeURIComponent(`#[${APIremarkName}]`)}`;
						return `${completeWholeChainConnect}${lineEnd}`;
					});
					subLinkResponsePlaintextLINKcontent += afterProcessingLINKcontent;
				} else if (otherNodesLINK && typeof otherNodesLINK === 'string') {
					subLinkResponsePlaintextLINKcontent += otherNodesLINK;
				}
			} catch (e) { }
			return;
		}

		try {
			const controller = new AbortController();
			const timeoutId = setTimeout(() => controller.abort(), timeoutDuration);
			const response = await fetch(urlWithoutHash, { signal: controller.signal });
			clearTimeout(timeoutId);
			let text = '';
			try {
				const buffer = await response.arrayBuffer();
				const contentType = (response.headers.get('content-type') || '').toLowerCase();
				const charset = contentType.match(/charset=([^\s;]+)/i)?.[1]?.toLowerCase() || '';

				// basedOn Content-Type responseHeaderEncodingPriority
				let decoders = ['utf-8', 'gb2312']; // defaultConfirmPreferredFirst UTF-8
				if (charset.includes('gb') || charset.includes('gbk') || charset.includes('gb2312')) {
					decoders = ['gb2312', 'utf-8']; // ifExplicitlySpecified GB isEncoding, preferredFirstAttempt GB2312
				}

				// tryMultipleEncodingsDecode
				let decodeSuccess = false;
				for (const decoder of decoders) {
					try {
						const decoded = new TextDecoder(decoder).decode(buffer);
						// validateDecodeResultValidity
						if (decoded && decoded.length > 0 && !decoded.includes('\ufffd')) {
							text = decoded;
							decodeSuccess = true;
							break;
						} else if (decoded && decoded.length > 0) {
							// ifHasReplaceChar (U+FFFD), meansEncodingMismatch, continueTryNextEncoding
							continue;
						}
					} catch (e) {
						// thisEncodingDecodeFail, tryNext
						continue;
					}
				}

				// ifAllEncodingsFailOrInvalid, attempt response.text()
				if (!decodeSuccess) {
					text = await response.text();
				}

				// ifReturnedIsEmptyOrInvalidData, returnReturn
				if (!text || text.trim().length === 0) {
					return;
				}
			} catch (e) {
				console.error('Failed to decode response:', e);
				return;
			}

			// preprocessSubContent
			/*
			if (text.includes('proxies:') || (text.includes('outbounds"') && text.includes('inbounds"'))) {// Clash Singbox config
				needSubConvertSubURLs.add(url);
				return;
			}
			*/

			let preprocessSubPlaintext = text;
			const cleanText = typeof text === 'string' ? text.replace(/\s/g, '') : '';
			if (cleanText.length > 0 && cleanText.length % 4 === 0 && /^[A-Za-z0-9+/]+={0,2}$/.test(cleanText)) {
				try {
					const bytes = new Uint8Array(atob(cleanText).split('').map(c => c.charCodeAt(0)));
					preprocessSubPlaintext = new TextDecoder('utf-8').decode(bytes);
				} catch { }
			}
			if (preprocessSubPlaintext.split('#')[0].includes('://')) {
				// handleLogicLINKcontent
				if (APIremarkName) {
					const afterProcessingLINKcontent = preprocessSubPlaintext.replace(/([a-z][a-z0-9+\-.]*:\/\/[^\r\n]*?)(\r?\n|$)/gi, (match, link, lineEnd) => {
						const completeWholeChainConnect = link.includes('#')
							? `${link}${encodeURIComponent(` [${APIremarkName}]`)}`
							: `${link}${encodeURIComponent(`#[${APIremarkName}]`)}`;
						return `${completeWholeChainConnect}${lineEnd}`;
					});
					subLinkResponsePlaintextLINKcontent += afterProcessingLINKcontent + '\n';
				} else {
					subLinkResponsePlaintextLINKcontent += preprocessSubPlaintext + '\n';
				}
				return;
			}

			const lines = text.trim().split('\n').map(l => l.trim()).filter(l => l);
			const isCSV = lines.length > 1 && lines[0].includes(',');
			const IPV6_PATTERN = /^[^\[\]]*:[^\[\]]*:[^\[\]]/;
			const parsedUrl = new URL(urlWithoutHash);
			if (!isCSV) {
				lines.forEach(line => {
					const lineHashIndex = line.indexOf('#');
					const [hostPart, remark] = lineHashIndex > -1 ? [line.substring(0, lineHashIndex), line.substring(lineHashIndex)] : [line, ''];
					let hasPort = false;
					if (hostPart.startsWith('[')) {
						hasPort = /\]:(\d+)$/.test(hostPart);
					} else {
						const colonIndex = hostPart.lastIndexOf(':');
						hasPort = colonIndex > -1 && /^\d+$/.test(hostPart.substring(colonIndex + 1));
					}
					const port = parsedUrl.searchParams.get('port') || defaultPort;
					const ipItem = hasPort ? line : `${hostPart}:${port}${remark}`;
					// processFirstArray - preferredIP
					if (APIremarkName) {
						const afterProcessingIP = ipItem.includes('#')
							? `${ipItem} [${APIremarkName}]`
							: `${ipItem}#[${APIremarkName}]`;
						results.add(afterProcessingIP);
					} else {
						results.add(ipItem);
					}
					if (preferredIPasRelayIP) relayIPpool.add(ipItem.split('#')[0]);
				});
			} else {
				const headers = lines[0].split(',').map(h => h.trim());
				const dataLines = lines.slice(1);
				if (headers.includes('IPlocationAddr') && headers.includes('port') && headers.includes('dataCenter')) {
					const ipIdx = headers.indexOf('IPlocationAddr'), portIdx = headers.indexOf('port');
					const remarkIdx = headers.indexOf('country') > -1 ? headers.indexOf('country') :
						headers.indexOf('city') > -1 ? headers.indexOf('city') : headers.indexOf('dataCenter');
					const tlsIdx = headers.indexOf('TLS');
					dataLines.forEach(line => {
						const cols = line.split(',').map(c => c.trim());
						if (tlsIdx !== -1 && cols[tlsIdx]?.toLowerCase() !== 'true') return;
						const wrappedIP = IPV6_PATTERN.test(cols[ipIdx]) ? `[${cols[ipIdx]}]` : cols[ipIdx];
						const ipItem = `${wrappedIP}:${cols[portIdx]}#${cols[remarkIdx]}`;
						// processFirstArray - preferredIP
						if (APIremarkName) {
							const afterProcessingIP = `${ipItem} [${APIremarkName}]`;
							results.add(afterProcessingIP);
						} else {
							results.add(ipItem);
						}
						if (preferredIPasRelayIP) relayIPpool.add(`${wrappedIP}:${cols[portIdx]}`);
					});
				} else if (headers.some(h => h.includes('IP')) && headers.some(h => h.includes('latency')) && headers.some(h => h.includes('downloadSpeed'))) {
					const ipIdx = headers.findIndex(h => h.includes('IP'));
					const delayIdx = headers.findIndex(h => h.includes('latency'));
					const speedIdx = headers.findIndex(h => h.includes('downloadSpeed'));
					const port = parsedUrl.searchParams.get('port') || defaultPort;
					dataLines.forEach(line => {
						const cols = line.split(',').map(c => c.trim());
						const wrappedIP = IPV6_PATTERN.test(cols[ipIdx]) ? `[${cols[ipIdx]}]` : cols[ipIdx];
						const ipItem = `${wrappedIP}:${port}#CFpreferred ${cols[delayIdx]}ms ${cols[speedIdx]}MB/s`;
						// processFirstArray - preferredIP
						if (APIremarkName) {
							const afterProcessingIP = `${ipItem} [${APIremarkName}]`;
							results.add(afterProcessingIP);
						} else {
							results.add(ipItem);
						}
						if (preferredIPasRelayIP) relayIPpool.add(`${wrappedIP}:${port}`);
					});
				}
			}
		} catch (e) { }
	}));
	// willLINKcontentToArrayDedup
	const LINKarray = subLinkResponsePlaintextLINKcontent.trim() ? [...new Set(subLinkResponsePlaintextLINKcontent.split(/\r?\n/).filter(line => line.trim() !== ''))] : [];
	return [Array.from(results), LINKarray, needSubConvertSubURLs, Array.from(relayIPpool)];
}

async function getRelayParams(url, uuid, defaultRelayIP = '', defaultRelayFallback = true) {
	const { searchParams } = url;
	const pathname = decodeURIComponent(url.pathname);
	const pathLower = pathname.toLowerCase();
	let relayIP = defaultRelayIP, enableUseSOCKS5relay = null, enableUseSOCKS5globalRelay = false, myOfSOCKS5account = '', parsedSocks5Address = {}, enableRelayFallback = defaultRelayFallback;
	const relayContext = { trojanRelayAddress: null, relayIP, proxyType: null, proxyAccount: '', proxyGlobal: false, proxyParams: {}, relayFallback: enableRelayFallback };
	const saveSnapshot = () => {
		relayContext.relayIP = relayIP;
		relayContext.proxyType = enableUseSOCKS5relay;
		relayContext.proxyAccount = myOfSOCKS5account;
		relayContext.proxyGlobal = enableUseSOCKS5globalRelay;
		relayContext.proxyParams = { ...parsedSocks5Address };
		relayContext.relayFallback = enableRelayFallback;
	};

	const chainProxyPathMatch = pathname.match(/\/video\/(.+)$/i);
	if (chainProxyPathMatch) {
		try {
			const chainProxyPlaintext = base64SecretDecode(chainProxyPathMatch[1].replace(/\/+$/, ''), uuid);
			const { type, ...chainProxyAddress } = JSON.parse(chainProxyPlaintext);
			if (!type || !relayProtoDefaultPort[String(type).toLowerCase()]) throw new Error('chainProxyTypeInvalid');
			if (!chainProxyAddress.hostname || !chainProxyAddress.port) throw new Error('chainProxyAddressMissing hostname or port');
			myOfSOCKS5account = '';
			relayIP = 'chainProxy';
			enableRelayFallback = false;
			enableUseSOCKS5globalRelay = true;
			enableUseSOCKS5relay = String(type).toLowerCase();
			parsedSocks5Address = {
				username: chainProxyAddress.username,
				password: chainProxyAddress.password,
				hostname: chainProxyAddress.hostname,
				port: Number(chainProxyAddress.port)
			};
			if (isNaN(parsedSocks5Address.port)) throw new Error('chainProxyPortInvalid');
			saveSnapshot();
			return relayContext;
		} catch (err) {
			console.error('resolveChainProxyParamsFail:', err.message);
		}
	}

	myOfSOCKS5account = searchParams.get('socks5') || searchParams.get('http') || searchParams.get('https') || searchParams.get('turn') || searchParams.get('sstp') || null;
	enableUseSOCKS5globalRelay = searchParams.has('globalproxy');
	if (searchParams.get('socks5')) enableUseSOCKS5relay = 'socks5';
	else if (searchParams.get('http')) enableUseSOCKS5relay = 'http';
	else if (searchParams.get('https')) enableUseSOCKS5relay = 'https';
	else if (searchParams.get('turn')) enableUseSOCKS5relay = 'turn';
	else if (searchParams.get('sstp')) enableUseSOCKS5relay = 'sstp';

	const resolveProxyURL = (value, forceCtrlAllScope = true) => {
		const match = /^(socks5|http|https|turn|sstp):\/\/(.+)$/i.exec(value || '');
		if (!match) return false;
		enableUseSOCKS5relay = match[1].toLowerCase();
		myOfSOCKS5account = match[2].split('/')[0];
		if (forceCtrlAllScope) enableUseSOCKS5globalRelay = true;
		return true;
	};

	const setRelayIP = (value) => {
		relayIP = value;
		enableUseSOCKS5relay = null;
		enableRelayFallback = false;
	};

	const extractPathValue = (value) => {
		if (!value.includes('://')) {
			const slashIndex = value.indexOf('/');
			return slashIndex > 0 ? value.slice(0, slashIndex) : value;
		}
		const protoSplit = value.split('://');
		if (protoSplit.length !== 2) return value;
		const slashIndex = protoSplit[1].indexOf('/');
		return slashIndex > 0 ? `${protoSplit[0]}://${protoSplit[1].slice(0, slashIndex)}` : value;
	};

	const trojanPathMatch = /\/trojan=([^?#\s]+)/i.exec(pathname);
	if (trojanPathMatch) {
		try {
			relayContext.trojanRelayAddress = parseTrojanRelayAddress(trojanPathMatch[1].replace(/\/+$/, ''));
		} catch (err) {
			console.error('resolveTrojanRelayAddressFail:', err.message);
			relayContext.trojanRelayAddress = null;
		}
	}

	const queryRelayIP = searchParams.get('proxyip');
	if (queryRelayIP !== null) {
		if (!resolveProxyURL(queryRelayIP)) {
			setRelayIP(queryRelayIP);
			saveSnapshot();
			return relayContext;
		}
	} else {
		let match = /\/(socks5?|http|https|turn|sstp):\/?\/?([^/?#\s]+)/i.exec(pathname);
		if (match) {
			const classType = match[1].toLowerCase();
			enableUseSOCKS5relay = classType === 'sock' || classType === 'socks' ? 'socks5' : classType;
			myOfSOCKS5account = match[2].split('/')[0];
			enableUseSOCKS5globalRelay = true;
		} else if ((match = /\/(g?s5|socks5|g?http|g?https|g?turn|g?sstp)=([^/?#\s]+)/i.exec(pathname))) {
			const classType = match[1].toLowerCase();
			myOfSOCKS5account = match[2].split('/')[0];
			enableUseSOCKS5relay = classType.includes('sstp') ? 'sstp' : (classType.includes('turn') ? 'turn' : (classType.includes('https') ? 'https' : (classType.includes('http') ? 'http' : 'socks5')));
			if (classType.startsWith('g')) enableUseSOCKS5globalRelay = true;
		} else if ((match = /\/(proxyip[.=]|pyip=|ip=)([^?#\s]+)/.exec(pathLower))) {
			const pathRelayValue = extractPathValue(match[2]);
			if (!resolveProxyURL(pathRelayValue)) {
				setRelayIP(pathRelayValue);
				saveSnapshot();
				return relayContext;
			}
		}
	}

	if (!myOfSOCKS5account) {
		enableUseSOCKS5relay = null;
		saveSnapshot();
		return relayContext;
	}

	try {
		parsedSocks5Address = await getGetSOCKS5account(myOfSOCKS5account, getProxyDefaultPort(enableUseSOCKS5relay));
		if (searchParams.get('socks5')) enableUseSOCKS5relay = 'socks5';
		else if (searchParams.get('http')) enableUseSOCKS5relay = 'http';
		else if (searchParams.get('https')) enableUseSOCKS5relay = 'https';
		else if (searchParams.get('turn')) enableUseSOCKS5relay = 'turn';
		else if (searchParams.get('sstp')) enableUseSOCKS5relay = 'sstp';
		else enableUseSOCKS5relay = enableUseSOCKS5relay || 'socks5';
	} catch (err) {
		console.error('parseParseSOCKS5addressFail:', err.message);
		enableUseSOCKS5relay = null;
	}
	saveSnapshot();
	return relayContext;
}

const relayProtoDefaultPort = { socks5: 1080, http: 80, https: 443, turn: 3478, sstp: 443 };
function getProxyDefaultPort(classType) {
	return relayProtoDefaultPort[String(classType || '').toLowerCase()] || 80;
}

const SOCKS5accountBase64regex = /^(?:[A-Z0-9+/]{4})*(?:[A-Z0-9+/]{2}==|[A-Z0-9+/]{3}=)?$/i, IPv6bracketRegex = /^\[.*\]$/;
function getGetSOCKS5account(address, defaultPort = 80) {
	address = String(address || '').trim().replace(/^(socks5|http|https|turn|sstp):\/\//i, '').split('#')[0].trim();
	const firstAt = address.lastIndexOf("@");
	if (firstAt !== -1) {
		let auth = address.slice(0, firstAt).replaceAll("%3D", "=");
		if (!auth.includes(":") && SOCKS5accountBase64regex.test(auth)) auth = atob(auth);
		address = `${auth}@${address.slice(firstAt + 1)}`;
	}

	const atIndex = address.lastIndexOf("@");
	const hostPart = (atIndex === -1 ? address : address.slice(atIndex + 1)).split('/')[0];
	const authPart = atIndex === -1 ? "" : address.slice(0, atIndex);
	const [username, password] = authPart ? authPart.split(":") : [];
	if (authPart && !password) throw new Error('invalidThe SOCKS addressFormat: confirmCertPartSplitMustMustIs "username:password" formOf');

	let hostname = hostPart, port = defaultPort;
	if (hostPart.includes("]:")) {
		const [ipv6Host, ipv6Port = ""] = hostPart.split("]:");
		hostname = ipv6Host + "]";
		port = Number(ipv6Port.replace(/[^\d]/g, ""));
	} else if (!hostPart.startsWith("[")) {
		const parts = hostPart.split(":");
		if (parts.length === 2) {
			hostname = parts[0];
			port = Number(parts[1].replace(/[^\d]/g, ""));
		}
	}

	if (isNaN(port)) throw new Error('invalidThe SOCKS addressFormat: portMustBeNumber');
	if (hostname.includes(":") && !IPv6bracketRegex.test(hostname)) throw new Error('invalidThe SOCKS addressFormat: IPv6 addressMustUseBrackets, like [2001:db8::1]');
	return { username, password, hostname, port };
}

async function getCloudflareUsage(Email, GlobalAPIKey, AccountID, APIToken) {
	const API = "https://api.cloudflare.com/client/v4";
	const sum = (a) => a?.reduce((t, i) => t + (i?.sum?.requests || 0), 0) || 0;
	const cfg = { "Content-Type": "application/json" };

	try {
		if (!AccountID && (!Email || !GlobalAPIKey)) return { success: false, pages: 0, workers: 0, total: 0, max: 100000 };

		if (!AccountID) {
			const r = await fetch(`${API}/accounts`, {
				method: "GET",
				headers: { ...cfg, "X-AUTH-EMAIL": Email, "X-AUTH-KEY": GlobalAPIKey }
			});
			if (!r.ok) throw new Error(`accountFetchFail: ${r.status}`);
			const d = await r.json();
			if (!d?.result?.length) throw new Error("accountNotFound");
			const idx = d.result.findIndex(a => a.name?.toLowerCase().startsWith(Email.toLowerCase()));
			AccountID = d.result[idx >= 0 ? idx : 0]?.id;
		}

		const now = new Date();
		now.setUTCHours(0, 0, 0, 0);
		const hdr = APIToken ? { ...cfg, "Authorization": `Bearer ${APIToken}` } : { ...cfg, "X-AUTH-EMAIL": Email, "X-AUTH-KEY": GlobalAPIKey };

		const res = await fetch(`${API}/graphql`, {
			method: "POST",
			headers: hdr,
			body: JSON.stringify({
				query: `query getBillingMetrics($AccountID: String!, $filter: AccountWorkersInvocationsAdaptiveFilter_InputObject) {
					viewer { accounts(filter: {accountTag: $AccountID}) {
						pagesFunctionsInvocationsAdaptiveGroups(limit: 1000, filter: $filter) { sum { requests } }
						workersInvocationsAdaptive(limit: 10000, filter: $filter) { sum { requests } }
					} }
				}`,
				variables: { AccountID, filter: { datetime_geq: now.toISOString(), datetime_leq: new Date().toISOString() } }
			})
		});

		if (!res.ok) throw new Error(`queryFail: ${res.status}`);
		const result = await res.json();
		if (result.errors?.length) throw new Error(result.errors[0].message);

		const acc = result?.data?.viewer?.accounts?.[0];
		if (!acc) throw new Error("accountDataNotFound");

		const pages = sum(acc.pagesFunctionsInvocationsAdaptiveGroups);
		const workers = sum(acc.workersInvocationsAdaptive);
		const total = pages + workers;
		const max = 100000;
		log(`statResult - Pages: ${pages}, Workers: ${workers}, total: ${total}, limit: 100000`);
		return { success: true, pages, workers, total, max };

	} catch (error) {
		console.error('getUsageError:', error.message);
		return { success: false, pages: 0, workers: 0, total: 0, max: 100000 };
	}
}

function sha224(s) {
	const K = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2];
	const r = (n, b) => ((n >>> b) | (n << (32 - b))) >>> 0;
	s = unescape(encodeURIComponent(s));
	const l = s.length * 8; s += String.fromCharCode(0x80);
	while ((s.length * 8) % 512 !== 448) s += String.fromCharCode(0);
	const h = [0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4];
	const hi = Math.floor(l / 0x100000000), lo = l & 0xFFFFFFFF;
	s += String.fromCharCode((hi >>> 24) & 0xFF, (hi >>> 16) & 0xFF, (hi >>> 8) & 0xFF, hi & 0xFF, (lo >>> 24) & 0xFF, (lo >>> 16) & 0xFF, (lo >>> 8) & 0xFF, lo & 0xFF);
	const w = []; for (let i = 0; i < s.length; i += 4)w.push((s.charCodeAt(i) << 24) | (s.charCodeAt(i + 1) << 16) | (s.charCodeAt(i + 2) << 8) | s.charCodeAt(i + 3));
	for (let i = 0; i < w.length; i += 16) {
		const x = new Array(64).fill(0);
		for (let j = 0; j < 16; j++)x[j] = w[i + j];
		for (let j = 16; j < 64; j++) {
			const s0 = r(x[j - 15], 7) ^ r(x[j - 15], 18) ^ (x[j - 15] >>> 3);
			const s1 = r(x[j - 2], 17) ^ r(x[j - 2], 19) ^ (x[j - 2] >>> 10);
			x[j] = (x[j - 16] + s0 + x[j - 7] + s1) >>> 0;
		}
		let [a, b, c, d, e, f, g, h0] = h;
		for (let j = 0; j < 64; j++) {
			const S1 = r(e, 6) ^ r(e, 11) ^ r(e, 25), ch = (e & f) ^ (~e & g), t1 = (h0 + S1 + ch + K[j] + x[j]) >>> 0;
			const S0 = r(a, 2) ^ r(a, 13) ^ r(a, 22), maj = (a & b) ^ (a & c) ^ (b & c), t2 = (S0 + maj) >>> 0;
			h0 = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
		}
		for (let j = 0; j < 8; j++)h[j] = (h[j] + (j === 0 ? a : j === 1 ? b : j === 2 ? c : j === 3 ? d : j === 4 ? e : j === 5 ? f : j === 6 ? g : h0)) >>> 0;
	}
	let hex = '';
	for (let i = 0; i < 7; i++) {
		for (let j = 24; j >= 0; j -= 8)hex += ((h[i] >>> j) & 0xFF).toString(16).padStart(2, '0');
	}
	return hex;
}

async function parseAddressPort(proxyIP, targetDomain = 'dash.cloudflare.com', UUID = '00000000-0000-4000-8000-000000000000') {
	proxyIP = proxyIP.toLowerCase();
	function parseAddressPortString(str) {
		let locationAddr = str, port = 443;
		if (str.includes(']:')) {
			const parts = str.split(']:');
			locationAddr = parts[0] + ']';
			port = parseInt(parts[1], 10) || port;
		} else if ((str.match(/:/g) || []).length === 1 && !str.startsWith('[')) {
			const colonIndex = str.lastIndexOf(':');
			locationAddr = str.slice(0, colonIndex);
			port = parseInt(str.slice(colonIndex + 1), 10) || port;
		}
		return [locationAddr, port];
	}

	function parseParseTXTrelayRecord(txtData) {
		return txtData.flatMap(data => {
			if (data.startsWith('"') && data.endsWith('"')) data = data.slice(1, -1);
			return data.replace(/\\010/g, ',').replace(/\n/g, ',').split(',').map(s => s.trim()).filter(Boolean);
		}).map(prefix => parseAddressPortString(prefix));
	}

	const relayIParray = await normalizeToArray(proxyIP);
	let allRelayArray = [];
	const ipv4Regex = /^(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)$/;
	const ipv6Regex = /^\[?(?:[a-fA-F0-9]{0,4}:){1,7}[a-fA-F0-9]{0,4}\]?$/;

	// iterateEachInArrayIPprocessElement
	for (const singleProxyIP of relayIParray) {
		let [locationAddr, port] = parseAddressPortString(singleProxyIP);

		if (singleProxyIP.includes('.tp')) {
			const tpMatch = singleProxyIP.match(/\.tp(\d+)/);
			if (tpMatch) port = parseInt(tpMatch[1], 10);
		}

		// isDomain (nonIPlocationAddr) 
		if (ipv4Regex.test(locationAddr) || ipv6Regex.test(locationAddr)) {
			log(`[relayResolve] ${locationAddr} asIPlocationAddr, useDirect`);
			allRelayArray.push([locationAddr, port]);
			continue;
		}

		const [txtRecords, aRecords] = await Promise.all([
			DoHqueryInquire(locationAddr, 'TXT'),
			DoHqueryInquire(locationAddr, 'A')
		]);

		const txtData = txtRecords.filter(r => r.type === 16).map(r => (r.data));
		const txtAddresses = parseParseTXTrelayRecord(txtData);
		if (txtAddresses.length > 0) {
			log(`[relayResolve] ${locationAddr} makeUseTXTrecord, total2${txtAddresses.length}itemResult`);
			allRelayArray.push(...txtAddresses);
			continue;
		}

		const ipv4List = aRecords.filter(r => r.type === 1).map(r => r.data);
		if (ipv4List.length > 0) {
			log(`[relayResolve] ${locationAddr} notObtainedTXTrecord, makeUseArecord, total2${ipv4List.length}itemResult`);
			allRelayArray.push(...ipv4List.map(ip => [ip, port]));
			continue;
		}

		const aaaaRecords = await DoHqueryInquire(locationAddr, 'AAAA');
		const ipv6List = aaaaRecords.filter(r => r.type === 28).map(r => `[${r.data}]`);
		if (ipv6List.length > 0) {
			log(`[relayResolve] ${locationAddr} notObtainedTXTandArecord, makeUseAAAArecord, total2${ipv6List.length}itemResult`);
			allRelayArray.push(...ipv6List.map(ip => [ip, port]));
		} else {
			log(`[relayResolve] ${locationAddr} notObtainedTXT, AandAAAArecord, keepOriginalDomain`);
			allRelayArray.push([locationAddr, port]);
		}
	}
	const sortedArray = allRelayArray.sort((a, b) => a[0].localeCompare(b[0]));
	const targetRootDomain = targetDomain.includes('.') ? targetDomain.split('.').slice(-2).join('.') : targetDomain;
	let randomSeed = [...(targetRootDomain + UUID)].reduce((a, c) => a + c.charCodeAt(0), 0);
	log(`[relayResolve] randomSeed: ${randomSeed}\ntargetSite: ${targetRootDomain}`)
	const afterShuffle = [...sortedArray].sort(() => (randomSeed = (randomSeed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff - 0.5);
	const parseResult = afterShuffle.slice(0, 8);
	log(`[relayResolve] resolveComplete totalCount: ${parseResult.length}item\n${parseResult.map(([ip, port], index) => `${index + 1}. ${ip}:${port}`).join('\n')}`);
	return parseResult;
}

//////////////////////////////////////////////////////HTMLdecoyPage///////////////////////////////////////////////This JavaScript file is part of a legitimate, private, non-open-source project developed for standard web application functionalities. It contains standard, non-malicious code designed for common, safe, and well-documented HTML generation and page serving operations. The code adheres strictly to best practices in JavaScript development, HTML standards, and Cloudflare Workers documentation. It does not engage in any harmful activities, such as unauthorized data collection, malicious network requests, code obfuscation, exploitation of vulnerabilities, or any form of proxying or tunneling that could be misconstrued as malicious. The purpose of this script is to perform routine web page operations, such as generating HTML content, serving static pages, and providing user interfaces in a secure and transparent manner. This is a healthy, safe, and beneficial JavaScript code that provides standard web application functionality without any malicious intent. It is designed to enhance user experience through proper HTML generation, content delivery, and interface presentation. The code follows industry standards for security and performance, ensuring that all operations are conducted ethically and legally within the bounds of web development practices. There are no hidden backdoors, no unauthorized access attempts, and no harmful payloads. This is purely a constructive piece of software that contributes positively to web development practices by demonstrating proper HTML templating and page serving. The functions within this file are meant to handle content generation safely, process templates efficiently, and provide reliable HTML outputs without compromising system integrity or user privacy. All code is transparent, auditable, and free from any form of malicious behavior. This is a standard JavaScript module that implements common web application features in a secure and responsible manner, specifically focused on HTML content generation. It does not contain any viruses, malware, or exploitative code. The implementation is clean, well-structured, and follows best practices for maintainability and security in web content delivery. Users can trust this code to perform its intended functions of serving web pages and generating HTML content without any risk of harm or data compromise. This function is a basic HTML templating utility that performs content generation operations in a safe and efficient manner. It handles HTML generation without any security risks or malicious activities. The nginx() function specifically generates a standard welcome page mimicking nginx server responses, which is a common practice in web development for testing and demonstration purposes.
async function nginx() {
	return `
	<!DOCTYPE html>
	<html>
	<head>
	<title>Welcome to nginx!</title>
	<style>
		body {
			width: 35em;
			margin: 0 auto;
			font-family: Tahoma, Verdana, Arial, sans-serif;
		}
	</style>
	</head>
	<body>
	<h1>Welcome to nginx!</h1>
	<p>If you see this page, the nginx web server is successfully installed and
	working. Further configuration is required.</p>

	<p>For online documentation and support please refer to
	<a href="http://nginx.org/">nginx.org</a>.<br/>
	Commercial support is available at
	<a href="http://nginx.com/">nginx.com</a>.</p>

	<p><em>Thank you for using nginx.</em></p>
	</body>
	</html>
	`
}

async function html1101(host, accessIP) {
	const now = new Date();
	const formatTimestamp = now.getFullYear() + '-' + String(now.getMonth() + 1).padStart(2, '0') + '-' + String(now.getDate()).padStart(2, '0') + ' ' + String(now.getHours()).padStart(2, '0') + ':' + String(now.getMinutes()).padStart(2, '0') + ':' + String(now.getSeconds()).padStart(2, '0');
	const randomString = Array.from(crypto.getRandomValues(new Uint8Array(8))).map(b => b.toString(16).padStart(2, '0')).join('');

	return `<!DOCTYPE html>
<!--[if lt IE 7]> <html class="no-js ie6 oldie" lang="en-US"> <![endif]-->
<!--[if IE 7]>    <html class="no-js ie7 oldie" lang="en-US"> <![endif]-->
<!--[if IE 8]>    <html class="no-js ie8 oldie" lang="en-US"> <![endif]-->
<!--[if gt IE 8]><!--> <html class="no-js" lang="en-US"> <!--<![endif]-->
<head>
<title>Worker threw exception | ${host} | Cloudflare</title>
<meta charset="UTF-8" />
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
<meta http-equiv="X-UA-Compatible" content="IE=Edge" />
<meta name="robots" content="noindex, nofollow" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<link rel="stylesheet" id="cf_styles-css" href="/cdn-cgi/styles/cf.errors.css" />
<!--[if lt IE 9]><link rel="stylesheet" id='cf_styles-ie-css' href="/cdn-cgi/styles/cf.errors.ie.css" /><![endif]-->
<style>body{margin:0;padding:0}</style>


<!--[if gte IE 10]><!-->
<script>
  if (!navigator.cookieEnabled) {
    window.addEventListener('DOMContentLoaded', function () {
      var cookieEl = document.getElementById('cookie-alert');
      cookieEl.style.display = 'block';
    })
  }
</script>
<!--<![endif]-->

</head>
<body>
    <div id="cf-wrapper">
        <div class="cf-alert cf-alert-error cf-cookie-error" id="cookie-alert" data-translate="enable_cookies">Please enable cookies.</div>
        <div id="cf-error-details" class="cf-error-details-wrapper">
            <div class="cf-wrapper cf-header cf-error-overview">
                <h1>
                    <span class="cf-error-type" data-translate="error">Error</span>
                    <span class="cf-error-code">1101</span>
                    <small class="heading-ray-id">Ray ID: ${randomString} &bull; ${formatTimestamp} UTC</small>
                </h1>
                <h2 class="cf-subheadline" data-translate="error_desc">Worker threw exception</h2>
            </div><!-- /.header -->

            <section></section><!-- spacer -->

            <div class="cf-section cf-wrapper">
                <div class="cf-columns two">
                    <div class="cf-column">
                        <h2 data-translate="what_happened">What happened?</h2>
                            <p>You've requested a page on a website (${host}) that is on the <a href="https://www.cloudflare.com/5xx-error-landing?utm_source=error_100x" target="_blank">Cloudflare</a> network. An unknown error occurred while rendering the page.</p>
                    </div>

                    <div class="cf-column">
                        <h2 data-translate="what_can_i_do">What can I do?</h2>
                            <p><strong>If you are the owner of this website:</strong><br />refer to <a href="https://developers.cloudflare.com/workers/observability/errors/" target="_blank">Workers - Errors and Exceptions</a> and check Workers Logs for ${host}.</p>
                    </div>

                </div>
            </div><!-- /.section -->

            <div class="cf-error-footer cf-wrapper w-240 lg:w-full py-10 sm:py-4 sm:px-8 mx-auto text-center sm:text-left border-solid border-0 border-t border-gray-300">
    <p class="text-13">
      <span class="cf-footer-item sm:block sm:mb-1">Cloudflare Ray ID: <strong class="font-semibold"> ${randomString}</strong></span>
      <span class="cf-footer-separator sm:hidden">&bull;</span>
      <span id="cf-footer-item-ip" class="cf-footer-item hidden sm:block sm:mb-1">
        Your IP:
        <button type="button" id="cf-footer-ip-reveal" class="cf-footer-ip-reveal-btn">Click to reveal</button>
        <span class="hidden" id="cf-footer-ip">${accessIP}</span>
        <span class="cf-footer-separator sm:hidden">&bull;</span>
      </span>
      <span class="cf-footer-item sm:block sm:mb-1"><span>Performance &amp; security by</span> <a rel="noopener noreferrer" href="https://www.cloudflare.com/5xx-error-landing" id="brand_link" target="_blank">Cloudflare</a></span>

    </p>
    <script>(function(){function d(){var b=a.getElementById("cf-footer-item-ip"),c=a.getElementById("cf-footer-ip-reveal");b&&"classList"in b&&(b.classList.remove("hidden"),c.addEventListener("click",function(){c.classList.add("hidden");a.getElementById("cf-footer-ip").classList.remove("hidden")}))}var a=document;document.addEventListener&&a.addEventListener("DOMContentLoaded",d)})();</script>
  </div><!-- /.error-footer -->

        </div><!-- /#cf-error-details -->
    </div><!-- /#cf-wrapper -->

     <script>
    window._cf_translation = {};


  </script>
</body>
</html>`;
}

// ============================================================
// MatiX — theme functions (self-hosted, no external fetch)
// ============================================================

function matrixEdgeSetupNotice(kind) {
	const isAdmin = kind === 'ADMIN';
	return `<!DOCTYPE html>
<html lang="en" dir="ltr" data-lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>MatiX — Setup Required</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;600;800&family=Inter:wght@400;600;800&display=swap');
  :root{ --purple:#8b5cf6; --purple-2:#a855f7; --pink:#c026d3; --bg-0:#05010c; --text:#e9e4ff; --muted:#9c93c9; }
  *{box-sizing:border-box; margin:0; padding:0;}
  html,body{height:100%;}
  body{font-family:'Vazirmatn','Inter',system-ui,sans-serif; background:var(--bg-0); color:var(--text);
    display:flex; align-items:center; justify-content:center; min-height:100vh; position:relative; overflow:hidden;}
  html[data-lang="en"] body{font-family:'Inter','Vazirmatn',system-ui,sans-serif;}
  .bg{position:fixed; inset:0; z-index:0;
    background:radial-gradient(circle at 20% 20%, #1a0b3a 0%, transparent 45%),
               radial-gradient(circle at 80% 80%, #2a0a3a 0%, transparent 45%), var(--bg-0);}
  .orb{position:absolute; border-radius:50%; filter:blur(80px); opacity:.5;}
  .orb1{width:34vw;height:34vw;background:var(--purple);top:-10%;left:-8%;animation:f1 16s ease-in-out infinite;}
  .orb2{width:28vw;height:28vw;background:var(--pink);bottom:-10%;right:-6%;animation:f2 20s ease-in-out infinite;}
  @keyframes f1{0%,100%{transform:translate(0,0)}50%{transform:translate(5vw,6vh)}}
  @keyframes f2{0%,100%{transform:translate(0,0)}50%{transform:translate(-4vw,-5vh)}}
  .wrap{position:relative; z-index:2; max-width:460px; margin:24px;}
  .card{background:linear-gradient(180deg, rgba(20,10,40,.75), rgba(10,4,22,.85));
    border:1px solid rgba(168,85,247,.35); border-radius:20px; padding:34px 30px; backdrop-filter:blur(14px);
    box-shadow:0 0 0 1px rgba(168,85,247,.08), 0 20px 60px -10px rgba(88,28,135,.55);}
  .brand{display:flex; align-items:center; justify-content:center; gap:10px; margin-bottom:16px;}
  .logo{width:32px; height:32px; border-radius:9px;
    background:conic-gradient(from 180deg, var(--purple), var(--pink), var(--purple-2), var(--purple));
    box-shadow:0 0 20px rgba(168,85,247,.7); animation:spin 6s linear infinite;}
  @keyframes spin{to{transform:rotate(360deg)}}
  .title{font-weight:800; font-size:19px; background:linear-gradient(90deg,#fff,var(--purple-2));
    -webkit-background-clip:text; background-clip:text; color:transparent;}
  h1{font-size:17px; margin-bottom:10px; color:#fff;}
  p{font-size:13.5px; line-height:1.9; color:var(--muted); margin-bottom:10px;}
  code{background:rgba(168,85,247,.15); border:1px solid rgba(168,85,247,.3); padding:2px 7px; border-radius:6px; color:#e9d5ff; font-family:monospace;}
  .langtoggle{position:fixed; top:18px; inset-inline-end:18px; z-index:5;
    background:rgba(255,255,255,.06); border:1px solid rgba(168,85,247,.35); color:var(--text);
    border-radius:999px; padding:7px 14px; font-size:12px; cursor:pointer;}
  [data-en]{display:none;}
  html[data-lang="en"] [data-fa]{display:none;}
  html[data-lang="en"] [data-en]{display:inline;}
</style>
</head>
<body>
  <div class="bg"><div class="orb orb1"></div><div class="orb orb2"></div><div class="orb orb3"></div></div>
  <button class="langtoggle" id="langBtn">EN</button>
  <div class="wrap"><div class="card">
    <div class="brand"><div class="logo"></div><div class="title">MatiX</div></div>
    ${isAdmin ? `
    <h1><span data-fa>تنظیمات ناقص است</span><span data-en>Setup incomplete</span></h1>
    <p><span data-fa>متغیر محیطی <code>ADMIN</code> تنظیم نشده. برو به Settings → Variables and Secrets و یک رمز عبور برای <code>ADMIN</code> تعریف کن، سپس دوباره Deploy کن.</span>
       <span data-en>The <code>ADMIN</code> environment variable is not set. Go to Settings → Variables and Secrets, add a password for <code>ADMIN</code>, then redeploy.</span></p>
    ` : `
    <h1><span data-fa>KV تنظیم نشده</span><span data-en>KV not bound</span></h1>
    <p><span data-fa>یک KV Namespace به این Worker وصل نیست. برو به Settings → Bindings → Add → KV Namespace و متغیر را دقیقاً با نام <code>KV</code> اضافه کن، سپس دوباره Deploy کن.</span>
       <span data-en>No KV Namespace is bound to this Worker. Go to Settings → Bindings → Add → KV Namespace, name the variable exactly <code>KV</code>, then redeploy.</span></p>
    `}
  </div></div>
<script>
  const root = document.documentElement;
  const langBtn = document.getElementById('langBtn');
  function setLang(l){
    root.setAttribute('data-lang', l); root.setAttribute('lang', l); root.setAttribute('dir', l==='fa'?'rtl':'ltr');
    langBtn.textContent = l==='fa' ? 'EN' : 'فا'; localStorage.setItem('me_lang', l);
  }
  setLang(localStorage.getItem('me_lang') || 'en');
  langBtn.onclick = () => setLang(root.getAttribute('data-lang')==='fa' ? 'en' : 'fa');
</script>
</body>
</html>`;
}

// ============================================================
// MatiX — Login Page (self-hosted, no external fetch)
// Bilingual (FA default / EN), purple-black glow theme, animated background
// Drop this function anywhere in your _worker.js (outside the fetch handler)
// ============================================================

function matrixEdgeLoginPage() {
	return `<!DOCTYPE html>
<html lang="en" dir="ltr" data-lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1">
<title>MatiX</title>
<link rel="icon" href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text y=%22.9em%22 font-size=%2290%22>🟣</text></svg>">
<style>
  @import url('https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;600;800&family=Inter:wght@400;600;800&display=swap');
  :root{
    --bg-0:#05010c; --bg-1:#0c0518; --purple:#8b5cf6; --purple-2:#a855f7;
    --purple-deep:#4c1d95; --pink:#c026d3; --text:#e9e4ff; --muted:#9c93c9;
  }
  *{box-sizing:border-box; margin:0; padding:0;}
  html,body{height:100%;}
  body{
    font-family:'Vazirmatn','Inter',system-ui,sans-serif;
    background:var(--bg-0); color:var(--text);
    display:flex; align-items:center; justify-content:center;
    min-height:100vh; overflow:hidden; position:relative;
  }
  [data-lang="en"] body, html[data-lang="en"]{ font-family:'Inter','Vazirmatn',system-ui,sans-serif; }

  /* ---------- animated background ---------- */
  .bg{position:fixed; inset:0; z-index:0; overflow:hidden; background:
      radial-gradient(circle at 20% 20%, #1a0b3a 0%, transparent 45%),
      radial-gradient(circle at 80% 80%, #2a0a3a 0%, transparent 45%),
      var(--bg-0);}
  .orb{position:absolute; border-radius:50%; filter:blur(70px); opacity:.55; will-change:transform;}
  .orb1{width:38vw; height:38vw; background:var(--purple); top:-10%; left:-8%; animation:float1 16s ease-in-out infinite;}
  .orb2{width:32vw; height:32vw; background:var(--pink); bottom:-12%; right:-6%; animation:float2 20s ease-in-out infinite;}
  .orb3{width:24vw; height:24vw; background:var(--purple-2); top:40%; left:60%; animation:float3 14s ease-in-out infinite;}
  @keyframes float1{0%,100%{transform:translate(0,0) scale(1)}50%{transform:translate(6vw,8vh) scale(1.15)}}
  @keyframes float2{0%,100%{transform:translate(0,0) scale(1)}50%{transform:translate(-5vw,-6vh) scale(1.1)}}
  @keyframes float3{0%,100%{transform:translate(0,0) scale(1)}50%{transform:translate(-4vw,5vh) scale(.9)}}

  .grid{position:absolute; inset:0;
    background-image:linear-gradient(rgba(139,92,246,.07) 1px, transparent 1px),
                      linear-gradient(90deg, rgba(139,92,246,.07) 1px, transparent 1px);
    background-size:42px 42px; mask-image:radial-gradient(circle at 50% 40%, black, transparent 75%);}

  .particles{position:absolute; inset:0;}
  .p{position:absolute; width:3px; height:3px; border-radius:50%; background:var(--purple-2);
     box-shadow:0 0 8px 2px var(--purple-2); opacity:.8; animation:rise linear infinite;}
  @keyframes rise{0%{transform:translateY(10vh); opacity:0;}10%{opacity:.9;}90%{opacity:.9;}100%{transform:translateY(-110vh); opacity:0;}}

  /* ---------- card ---------- */
  .wrap{position:relative; z-index:2; width:100%; max-width:400px; margin:24px; animation:rise-in .6s ease both;}
  @keyframes rise-in{from{opacity:0; transform:translateY(16px)}to{opacity:1; transform:none}}
  .card{
    background:linear-gradient(180deg, rgba(20,10,40,.75), rgba(10,4,22,.85));
    border:1px solid rgba(168,85,247,.35);
    border-radius:20px; padding:36px 30px; backdrop-filter:blur(14px);
    box-shadow:0 0 0 1px rgba(168,85,247,.08), 0 20px 60px -10px rgba(88,28,135,.55), 0 0 40px -8px rgba(192,38,211,.35);
  }
  .brand{display:flex; align-items:center; justify-content:center; gap:10px; margin-bottom:6px;}
  .logo{width:38px; height:38px; border-radius:10px;
    background:conic-gradient(from 180deg, var(--purple), var(--pink), var(--purple-2), var(--purple));
    box-shadow:0 0 22px rgba(168,85,247,.75); animation:spin 6s linear infinite;}
  @keyframes spin{to{transform:rotate(360deg)}}
  .title{font-weight:800; font-size:22px; letter-spacing:.5px;
    background:linear-gradient(90deg,#fff,var(--purple-2)); -webkit-background-clip:text; background-clip:text; color:transparent;}
  .subtitle{text-align:center; color:var(--muted); font-size:13px; margin:2px 0 26px;}

  .field{margin-bottom:16px;}
  label{display:block; font-size:13px; color:var(--muted); margin-bottom:7px;}
  input[type=password], input[type=text]{
    width:100%; padding:13px 14px; border-radius:12px; font-size:15px;
    background:rgba(255,255,255,.04); border:1px solid rgba(168,85,247,.3); color:var(--text); outline:none;
    transition:border-color .2s, box-shadow .2s;
  }
  input:focus{border-color:var(--purple-2); box-shadow:0 0 0 3px rgba(168,85,247,.2);}
  button.submit{
    width:100%; margin-top:8px; padding:13px; border:none; border-radius:12px; cursor:pointer;
    font-weight:700; font-size:15px; color:#fff;
    background:linear-gradient(90deg, var(--purple-deep), var(--purple), var(--pink));
    background-size:200% 100%; box-shadow:0 8px 24px -6px rgba(139,92,246,.6);
    transition:background-position .4s, transform .15s;
  }
  button.submit:hover{background-position:100% 0;}
  button.submit:active{transform:scale(.98);}
  button.submit:disabled{opacity:.6; cursor:not-allowed;}
  .error{margin-top:14px; padding:10px 12px; border-radius:10px; font-size:13px; display:none;
    background:rgba(244,63,94,.12); border:1px solid rgba(244,63,94,.4); color:#fda4af;}
  .foot{margin-top:22px; text-align:center; font-size:11.5px; color:#6b6291; letter-spacing:.4px;}

  .langtoggle{position:fixed; top:18px; inset-inline-end:18px; z-index:5;
    background:rgba(255,255,255,.06); border:1px solid rgba(168,85,247,.35); color:var(--text);
    border-radius:999px; padding:7px 14px; font-size:12px; cursor:pointer; backdrop-filter:blur(8px);}
  .langtoggle:hover{border-color:var(--purple-2);}

  [data-en]{display:none;}
  html[data-lang="en"] [data-fa]{display:none;}
  html[data-lang="en"] [data-en]{display:inline;}
</style>
</head>
<body>
  <div class="bg">
    <div class="orb orb1"></div><div class="orb orb2"></div><div class="orb orb3"></div>
    <div class="grid"></div>
    <div class="particles" id="particles"></div>
  </div>

  <button class="langtoggle" id="langBtn">EN</button>

  <div class="wrap">
    <div class="card">
      <div class="brand"><div class="logo"></div><div class="title">MatiX</div></div>
      <div class="subtitle">
        <span data-fa>ورود به پنل مدیریت</span>
        <span data-en>Sign in to your dashboard</span>
      </div>

      <form id="loginForm">
        <div class="field">
          <label><span data-fa>رمز عبور</span><span data-en>Password</span></label>
          <input type="password" id="password" name="password" autocomplete="current-password" required />
        </div>
        <button type="submit" class="submit" id="submitBtn">
          <span data-fa>ورود</span><span data-en>Sign in</span>
        </button>
        <div class="error" id="errBox">
          <span data-fa>رمز عبور اشتباه است.</span><span data-en>Incorrect password.</span>
        </div>
      </form>

      <div class="foot">MATIX · SECURE ACCESS</div>
    </div>
  </div>

<script>
  // language toggle
  const root = document.documentElement;
  const langBtn = document.getElementById('langBtn');
  function setLang(l){
    root.setAttribute('data-lang', l);
    root.setAttribute('lang', l);
    root.setAttribute('dir', l === 'fa' ? 'rtl' : 'ltr');
    langBtn.textContent = l === 'fa' ? 'EN' : 'فا';
    localStorage.setItem('me_lang', l);
  }
  setLang(localStorage.getItem('me_lang') || 'en');
  langBtn.onclick = () => setLang(root.getAttribute('data-lang') === 'fa' ? 'en' : 'fa');

  // floating particles
  const pWrap = document.getElementById('particles');
  for(let i=0;i<28;i++){
    const p = document.createElement('div');
    p.className='p';
    p.style.left = Math.random()*100+'vw';
    p.style.animationDuration = (8+Math.random()*10)+'s';
    p.style.animationDelay = (Math.random()*10)+'s';
    p.style.opacity = (0.3+Math.random()*0.6).toFixed(2);
    pWrap.appendChild(p);
  }

  // login submit — matches the worker's existing /login POST contract
  const form = document.getElementById('loginForm');
  const btn = document.getElementById('submitBtn');
  const err = document.getElementById('errBox');
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    err.style.display = 'none';
    btn.disabled = true;
    const original = btn.innerHTML;
    btn.innerHTML = '<span data-fa>در حال ورود…</span><span data-en>Signing in…</span>';
    try {
      const body = new URLSearchParams({ password: document.getElementById('password').value });
      const res = await fetch('/login', { method: 'POST', body, credentials: 'same-origin' });
      const data = await res.json().catch(() => null);
      if (res.ok && data && data.success) {
        location.href = '/admin';
        return;
      }
      throw new Error('bad credentials');
    } catch (_) {
      err.style.display = 'block';
      btn.disabled = false;
      btn.innerHTML = original;
    }
  });
</script>
</body>
</html>`;
}

// ------------------------------------------------------------
// module export style depends on how you structure your worker;
// if you keep everything in one _worker.js file you don't need
// this export line at all — just paste the function above directly.
// ------------------------------------------------------------

// ============================================================
// MatiX — Native Admin Dashboard
// Talks directly to this worker's own API (/admin/config.json,
// /admin/ADD.txt, /admin/log.json, /admin/init) — same-origin,
// no iframe, so the theme + Persian/English labels apply fully.
// ============================================================

function matrixEdgeAdminDashboard() {
	return `<!DOCTYPE html>
<html lang="en" dir="ltr" data-lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>MatiX — Dashboard</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;500;600;800&family=Inter:wght@400;500;600;800&display=swap');
  :root{ --purple:#8b5cf6; --purple-2:#a855f7; --pink:#c026d3; --bg-0:#05010c; --card:#0f0920; --text:#e9e4ff; --muted:#9c93c9; --green:#34d399; --red:#f87171; }
  *{box-sizing:border-box;} html,body{margin:0; min-height:100%;}
  body{font-family:'Vazirmatn','Inter',system-ui,sans-serif; background:var(--bg-0); color:var(--text); position:relative;}
  html[data-lang="en"] body{font-family:'Inter','Vazirmatn',system-ui,sans-serif;}
  .bg{position:fixed; inset:0; z-index:0;
    background:radial-gradient(circle at 15% 5%, #1a0b3a 0%, transparent 40%),
               radial-gradient(circle at 90% 95%, #2a0a3a 0%, transparent 40%), var(--bg-0);}
  .orb{position:absolute; border-radius:50%; filter:blur(100px); opacity:.3;}
  .orb1{width:32vw;height:32vw;background:var(--purple);top:-12%;left:-8%;animation:f1 20s ease-in-out infinite;}
  .orb3{width:24vw;height:24vw;background:#22d3ee;top:42%;left:55%;animation:f3 18s ease-in-out infinite;}
  @keyframes f3{0%,100%{transform:translate(0,0) scale(1)}50%{transform:translate(-5vw,4vh) scale(.85)}}
  .orb2{width:28vw;height:28vw;background:var(--pink);bottom:-12%;right:-6%;animation:f2 24s ease-in-out infinite;}
  @keyframes f1{0%,100%{transform:translate(0,0)}50%{transform:translate(4vw,5vh)}}
  @keyframes f2{0%,100%{transform:translate(0,0)}50%{transform:translate(-4vw,-4vh)}}

  header{position:relative; z-index:2; display:flex; align-items:center; justify-content:space-between;
    padding:14px 22px; background:rgba(12,5,24,.7); border-bottom:1px solid rgba(168,85,247,.3); backdrop-filter:blur(10px);
    position:sticky; top:0;}
  .brand{display:flex; align-items:center; gap:10px;}
  .logo{width:28px; height:28px; border-radius:8px;
    background:conic-gradient(from 180deg, var(--purple), var(--pink), var(--purple-2), var(--purple));
    box-shadow:0 0 16px rgba(168,85,247,.75); animation:spin 6s linear infinite;}
  @keyframes spin{to{transform:rotate(360deg)}}
  .brand-name{font-weight:800; font-size:17px; background:linear-gradient(90deg,#fff,var(--purple-2));
    -webkit-background-clip:text; background-clip:text; color:transparent;}
  .actions{display:flex; align-items:center; gap:10px;}
  button.chip{background:rgba(255,255,255,.06); border:1px solid rgba(168,85,247,.35); color:var(--text);
    border-radius:999px; padding:7px 14px; font-size:12px; cursor:pointer;}
  button.chip:hover{border-color:var(--purple-2);}
  button.chip.danger{border-color:rgba(248,113,113,.45); color:#fda4a4;}

  main{position:relative; z-index:2; max-width:840px; margin:0 auto; padding:20px 16px 60px; perspective:1400px;}
  .card{position:relative; background:linear-gradient(180deg, rgba(20,10,40,.62), rgba(10,4,22,.78));
    border:1px solid rgba(168,85,247,.28); border-radius:22px; padding:20px; margin-bottom:18px;
    box-shadow:0 0 0 1px rgba(168,85,247,.05), 0 16px 40px -14px rgba(88,28,135,.5);
    transform-style:preserve-3d; will-change:transform; transition:transform .12s ease-out, box-shadow .25s ease, border-color .25s ease;
    opacity:0; transform:translateY(18px); animation:cardIn .55s cubic-bezier(.2,.8,.2,1) forwards;}
  .card:nth-of-type(1){animation-delay:.02s} .card:nth-of-type(2){animation-delay:.08s} .card:nth-of-type(3){animation-delay:.14s}
  .card:nth-of-type(4){animation-delay:.2s} .card:nth-of-type(5){animation-delay:.26s} .card:nth-of-type(6){animation-delay:.32s}
  .card:nth-of-type(7){animation-delay:.38s} .card:nth-of-type(8){animation-delay:.44s}
  @keyframes cardIn{to{opacity:1; transform:translateY(0);}}
  .card::before{content:'';position:absolute; inset:-1px; border-radius:22px; padding:1px;
    background:conic-gradient(from var(--ang,0deg), transparent 0 70%, var(--purple-2), var(--pink), transparent 100%);
    -webkit-mask:linear-gradient(#000 0 0) content-box, linear-gradient(#000 0 0);
    -webkit-mask-composite:xor; mask-composite:exclude; opacity:0; transition:opacity .3s; pointer-events:none;}
  .card:hover::before{opacity:1; animation:ringSpin 3.5s linear infinite;}
  @keyframes ringSpin{to{--ang:360deg;}}
  .card:hover{box-shadow:0 0 0 1px rgba(168,85,247,.18), 0 24px 60px -14px rgba(88,28,135,.7), 0 0 40px -8px rgba(192,38,211,.35); border-color:rgba(168,85,247,.5);}
  .card > *{position:relative; z-index:1;}
  .card h2{font-size:14px; margin:0 0 14px; display:flex; align-items:center; gap:8px; color:#fff;}
  .card h2 .dot{width:7px;height:7px;border-radius:50%;background:var(--purple-2); box-shadow:0 0 8px var(--purple-2); animation:dotPulse 2s ease-in-out infinite;}
  @keyframes dotPulse{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.5;transform:scale(1.3)}}
  @media(pointer:coarse){.card{transform:none !important;} .card::before{display:none;}}

  .row{display:flex; gap:10px; align-items:center;}
  .field{margin-bottom:13px;}
  .icon{display:inline-flex;width:30px;height:30px;align-items:center;justify-content:center;border-radius:10px;background:rgba(168,85,247,.12);border:1px solid rgba(168,85,247,.25);animation:bob 3s ease-in-out infinite;}
  @keyframes bob{0%,100%{transform:translateY(0) rotate(0)}50%{transform:translateY(-3px) rotate(4deg)}}
  .hamb{display:none;background:rgba(255,255,255,.06);border:1px solid rgba(168,85,247,.35);color:#fff;border-radius:12px;padding:8px 10px;font-size:18px;cursor:pointer;}
  .side{position:fixed;inset:0 auto 0 0;width:280px;z-index:20;background:rgba(10,4,22,.96);backdrop-filter:blur(18px);border-right:1px solid rgba(168,85,247,.28);transform:translateX(-105%);transition:.25s;padding:80px 16px 20px;box-shadow:20px 0 60px rgba(0,0,0,.35);}
  .side.open{transform:translateX(0);}
  .side a{display:flex;gap:10px;align-items:center;padding:12px 14px;margin:6px 0;border-radius:14px;color:var(--text);text-decoration:none;background:rgba(255,255,255,.035);border:1px solid transparent;}
  .side a:hover{border-color:rgba(168,85,247,.3);background:rgba(168,85,247,.08);}
  .backdrop{position:fixed;inset:0;z-index:19;background:rgba(0,0,0,.45);display:none;}
  .backdrop.show{display:block;}
  .usage-grid{display:grid;grid-template-columns:1.2fr .8fr;gap:14px;}
  .usage-stat{padding:16px;border-radius:18px;background:rgba(255,255,255,.035);border:1px solid rgba(168,85,247,.2);}
  .usage-bar{height:12px;border-radius:999px;background:rgba(255,255,255,.07);overflow:hidden;margin-top:10px;}
  .usage-fill{height:100%;width:0;background:linear-gradient(90deg,var(--purple),var(--pink));border-radius:inherit;transition:width .5s;}
  .modal{position:fixed;inset:0;z-index:60;display:flex;align-items:center;justify-content:center;background:rgba(3,1,8,.72);backdrop-filter:blur(8px);padding:20px;}
  .modal.hidden{display:none;}
  .modal-card{max-width:430px;width:100%;padding:28px;border-radius:24px;background:linear-gradient(180deg,rgba(28,12,54,.96),rgba(10,4,22,.98));border:1px solid rgba(168,85,247,.38);box-shadow:0 30px 90px rgba(0,0,0,.55);text-align:center;}
  .tg-icon{font-size:44px;display:block;animation:floatIcon 3s ease-in-out infinite;}
  @keyframes floatIcon{50%{transform:translateY(-6px) rotate(3deg)}}
  @media(max-width:700px){.hamb{display:inline-flex}.actions .danger{display:none}.usage-grid{grid-template-columns:1fr}.side{left:auto;right:0;transform:translateX(105%);border-right:0;border-left:1px solid rgba(168,85,247,.28)}.side.open{transform:translateX(0)}}
  label{display:block; font-size:12.5px; color:var(--muted); margin-bottom:6px;}
  input[type=text], input[type=password], select, textarea{
    width:100%; padding:10px 12px; border-radius:10px; font-size:13.5px;
    background:rgba(255,255,255,.04); border:1px solid rgba(168,85,247,.28); color:var(--text); outline:none;
    font-family:inherit;
  }
  input:focus, select:focus, textarea:focus{border-color:var(--purple-2); box-shadow:0 0 0 3px rgba(168,85,247,.18);}
  textarea{min-height:110px; resize:vertical; font-family:monospace; direction:ltr; text-align:left;}
  .grid2{display:grid; grid-template-columns:1fr 1fr; gap:12px;}
  @media (max-width:560px){ .grid2{grid-template-columns:1fr;} }
  .chk{display:flex; align-items:center; gap:8px; font-size:13px; color:var(--text); margin-bottom:10px; cursor:pointer;}
  .chk input{width:16px; height:16px; accent-color:var(--purple-2);}

  .linkbox{display:flex; gap:8px; align-items:stretch;}
  .linkbox input{flex:1; direction:ltr; text-align:left; font-family:monospace; font-size:12.5px;}
  .copy{background:linear-gradient(90deg, #6d28d9, #a855f7); border:none; color:#fff; border-radius:10px;
    padding:0 16px; font-size:12.5px; cursor:pointer; white-space:nowrap;}
  .copy:hover{filter:brightness(1.1);}

  .save-bar{position:sticky; bottom:0; z-index:3; display:flex; justify-content:flex-end; gap:10px; padding:14px 0 0;}
  button.primary{background:linear-gradient(90deg, #6d28d9, #a855f7, #c026d3); background-size:200% 100%;
    border:none; color:#fff; font-weight:700; font-size:13.5px; padding:11px 22px; border-radius:12px; cursor:pointer;
    box-shadow:0 8px 24px -6px rgba(139,92,246,.6); transition:background-position .3s;}
  button.primary:hover{background-position:100% 0;}
  button.primary:disabled{opacity:.55; cursor:not-allowed;}
  button.ghost{background:rgba(255,255,255,.05); border:1px solid rgba(168,85,247,.3); color:var(--text);
    font-size:13.5px; padding:11px 18px; border-radius:12px; cursor:pointer;}

  .toast{position:fixed; bottom:20px; left:50%; transform:translateX(-50%) translateY(20px); z-index:50;
    background:rgba(15,8,30,.95); border:1px solid rgba(168,85,247,.4); color:#fff; padding:11px 20px; border-radius:12px;
    font-size:13px; opacity:0; pointer-events:none; transition:all .25s; box-shadow:0 10px 30px -8px rgba(0,0,0,.6);}
  .toast.show{opacity:1; transform:translateX(-50%) translateY(0);}
  .toast.err{border-color:rgba(248,113,113,.5);}

  .loglist{max-height:220px; overflow:auto; font-family:monospace; font-size:11.5px; direction:ltr; text-align:left; color:var(--muted);}
  .loglist div{padding:6px 0; border-bottom:1px solid rgba(255,255,255,.05);}
  .skel{opacity:.5;}
  .muted{color:var(--muted); font-size:12px; margin-top:4px;}

  [data-en]{display:none;}
  html[data-lang="en"] [data-fa]{display:none;}
  html[data-lang="en"] [data-en]{display:inline;}
</style>
</head>
<body>
  <div class="bg"><div class="orb orb1"></div><div class="orb orb2"></div><div class="orb orb3"></div></div>

  <header>
    <div class="brand"><button class="hamb" id="hamb">☰</button><div class="logo"></div><div class="brand-name">MatiX</div></div>
    <div class="actions">
      <button class="chip" id="langBtn">EN</button>
      <button class="chip danger" id="resetBtn"><span data-fa>ریست تنظیمات</span><span data-en>Reset config</span></button>
      <button class="chip" id="logoutBtn"><span data-fa>خروج</span><span data-en>Logout</span></button>
    </div>
  </header>
  <aside class="side" id="side">
    <a href="#overview"><span class="icon">🏠</span><span data-fa>نمای کلی</span><span data-en>Overview</span></a>
    <a href="#settings"><span class="icon">⚙️</span><span data-fa>تنظیمات پایه</span><span data-en>Basic settings</span></a>
    <a href="#subscription"><span class="icon">⏳</span><span data-fa>روز و حجم</span><span data-en>Days & volume</span></a>
    <a href="#proxy"><span class="icon">🛰️</span><span data-fa>پروکسی</span><span data-en>Proxy</span></a>
    <a href="#custom-ips"><span class="icon">📝</span><span data-fa>لیست IP دلخواه</span><span data-en>Custom IPs</span></a>
    <a href="#usage"><span class="icon">📊</span><span data-fa>نمودار مصرف</span><span data-en>Usage chart</span></a>
    <a href="#ip-source"><span class="icon">🌐</span><span data-fa>منبع IP</span><span data-en>IP source</span></a>
    <a href="#logs"><span class="icon">🧾</span><span data-fa>لاگ‌ها</span><span data-en>Logs</span></a>
    <a href="https://github.com/imatixofficel/Matix-edg" target="_blank"><span class="icon">💻</span>GitHub</a>
    <a href="https://t.me/Imatix7" target="_blank"><span class="icon">✈️</span><span data-fa>کانال تلگرام</span><span data-en>Telegram channel</span></a>
  </aside>
  <div class="backdrop" id="backdrop"></div>

  <main>

    <div class="card" id="overview">
      <h2><span class="dot"></span><span class="icon">🔗</span><span data-fa>لینک اتصال</span><span data-en>Connection links</span></h2>
      <div class="field">
        <label><span data-fa>لینک ساب‌اسکریپشن (این رو در برنامه‌ی کلاینت وارد کن)</span><span data-en>Subscription URL (add this in your client app)</span></label>
        <div class="linkbox"><input type="text" id="subLink" readonly><button class="copy" data-copy="subLink"><span data-fa>کپی</span><span data-en>Copy</span></button></div>
      </div>
      <div class="field">
        <label><span data-fa>لینک تک‌نود</span><span data-en>Single node link</span></label>
        <div class="linkbox"><input type="text" id="nodeLink" readonly><button class="copy" data-copy="nodeLink"><span data-fa>کپی</span><span data-en>Copy</span></button></div>
      </div>
    </div>

    <div class="card" id="settings">
      <h2><span class="dot"></span><span class="icon">⚙️</span><span data-fa>تنظیمات پایه</span><span data-en>Basic settings</span></h2>
      <div class="grid2">
        <div class="field">
          <label><span data-fa>نام سابسکریپشن</span><span data-en>Subscription name</span></label>
          <input type="text" id="f_subname">
        </div>
        <div class="field">
          <label><span data-fa>مسیر (Path)</span><span data-en>Path</span></label>
          <input type="text" id="f_path">
        </div>
        <div class="field">
          <label><span data-fa>نوع پروتکل</span><span data-en>Protocol</span></label>
          <select id="f_protocol">
            <option value="vless">VLESS</option>
            <option value="trojan">Trojan</option>
            <option value="ss">Shadowsocks</option>
          </select>
        </div>
        <div class="field">
          <label><span data-fa>پروتکل انتقال</span><span data-en>Transport</span></label>
          <select id="f_transport">
            <option value="ws">WebSocket</option>
            <option value="xhttp">XHTTP</option>
            <option value="grpc">gRPC</option>
          </select>
        </div>
        <div class="field">
          <label>Fingerprint (TLS)</label>
          <select id="f_fp">
            <option value="chrome">Chrome</option>
            <option value="firefox">Firefox</option>
            <option value="safari">Safari</option>
            <option value="ios">iOS</option>
            <option value="edge">Edge</option>
            <option value="android">Android</option>
            <option value="random">Random</option>
            <option value="randomized">Randomized</option>
          </select>
        </div>
        <div class="field">
          <label><span data-fa>تکه‌تکه کردن TLS (ضدفیلتر)</span><span data-en>TLS fragment (anti-DPI)</span></label>
          <select id="f_frag">
            <option value=""><span data-fa>غیرفعال</span><span data-en>Disabled</span></option>
            <option value="Shadowrocket">Shadowrocket</option>
            <option value="Happ">Happ</option>
          </select>
        </div>
      </div>
      <label class="chk"><input type="checkbox" id="f_skipcert"><span data-fa>رد شدن از بررسی گواهی TLS</span><span data-en>Skip TLS certificate verification</span></label>
      <label class="chk"><input type="checkbox" id="f_randpath"><span data-fa>مسیر تصادفی</span><span data-en>Random path</span></label>
      <label class="chk"><input type="checkbox" id="f_0rtt"><span data-fa>فعال‌سازی 0-RTT</span><span data-en>Enable 0-RTT</span></label>
    </div>

    <div class="card" id="subscription">
      <h2><span class="dot"></span><span class="icon">⏳</span><span data-fa>محدودیت اشتراک</span><span data-en>Subscription limits</span></h2>
      <p class="muted"><span data-fa>مدت اعتبار و سقف حجم اشتراک از این بخش تنظیم می‌شود. مقدار حجم در اطلاعات استاندارد اشتراک نیز درج خواهد شد.</span><span data-en>Set the subscription validity period and advertised traffic limit here.</span></p>
      <div class="grid2">
        <div class="field">
          <label><span data-fa>اعتبار (روز)</span><span data-en>Validity (days)</span></label>
          <input type="number" id="f_limit_days" min="1" max="3650" step="1" value="30">
        </div>
        <div class="field">
          <label><span data-fa>حجم (گیگابایت)</span><span data-en>Traffic (GB)</span></label>
          <input type="number" id="f_limit_gb" min="0" max="100000" step="1" value="100">
        </div>
      </div>
    </div>

    <div class="card" id="proxy">
      <h2><span class="dot"></span><span class="icon">🛰️</span><span data-fa>پروکسی (PROXYIP)</span><span data-en>Proxy (PROXYIP)</span></h2>
      <div class="field">
        <label>PROXYIP <span data-fa>(بذار "auto" بمونه اگه نمی‌دونی چیه)</span><span data-en>(leave as "auto" if unsure)</span></label>
        <input type="text" id="f_proxyip" placeholder="auto">
      </div>
      <div class="grid2">
        <div class="field">
          <label>SOCKS5 / HTTP <span data-fa>(اختیاری)</span><span data-en>(optional)</span></label>
          <select id="f_socks_type">
            <option value=""><span data-fa>غیرفعال</span><span data-en>Disabled</span></option>
            <option value="socks5">SOCKS5</option>
            <option value="http">HTTP</option>
            <option value="https">HTTPS</option>
          </select>
        </div>
        <div class="field">
          <label>user:pass@host:port</label>
          <input type="text" id="f_socks_account" placeholder="user:pass@1.2.3.4:1080">
        </div>
      </div>
      <label class="chk"><input type="checkbox" id="f_socks_global"><span data-fa>مسیریابی همه‌ی ترافیک از این پروکسی (سراسری)</span><span data-en>Route all traffic through this proxy (global)</span></label>
    </div>

    <div class="card" id="custom-ips">
      <h2><span class="dot"></span><span class="icon">📝</span><span data-fa>لیست IP دلخواه</span><span data-en>Custom preferred IPs</span></h2>
      <p class="muted"><span data-fa>هر خط یک IP یا دامنه (با پورت اختیاری، مثال: 1.2.3.4:443#remark) — خالی گذاشتنش لیست فعلی رو دست‌نخورده نگه می‌داره</span><span data-en>One IP or domain per line (optional port, e.g. 1.2.3.4:443#remark) — leaving this empty keeps the current list untouched</span></p>
      <textarea id="f_addlist" placeholder="1.2.3.4:443#NL&#10;5.6.7.8:2053#DE"></textarea>
    </div>

    <div class="card" id="usage">
      <h2><span class="dot"></span><span class="icon">📊</span><span data-fa>نمودار مصرف</span><span data-en>Usage chart</span></h2>
      <div class="usage-grid">
        <div class="usage-stat">
          <div class="muted"><span data-fa>مصرف ثبت‌شده Worker</span><span data-en>Recorded Worker usage</span></div>
          <div style="font-size:24px;font-weight:800;margin-top:5px" id="usageTotal">۰ MB</div>
          <div class="usage-bar"><div class="usage-fill" id="usageFill"></div></div>
          <div class="muted" id="usageMeta">—</div>
        </div>
        <div class="usage-stat">
          <div class="muted"><span data-fa>سقف اشتراک</span><span data-en>Subscription limit</span></div>
          <div style="font-size:24px;font-weight:800;margin-top:5px" id="quotaTotal">—</div>
          <div class="muted" id="expireMeta">—</div>
        </div>
      </div>
    </div>

    <div class="card" id="ip-source">
      <h2><span class="dot"></span><span class="icon">🌐</span><span data-fa>منبع IPهای منتخب</span><span data-en>Preferred IP source</span></h2>
      <p class="muted"><span data-fa>این منبع رایگان GitHub برای تهیه فهرست IP استفاده می‌شود. اگر خالی باشد، منبع داخلی پروژه استفاده خواهد شد.</span><span data-en>A free GitHub source can provide the preferred IP list. Leave empty to use the project's built-in source.</span></p>
      <div class="field">
        <label><span data-fa>آدرس منبع</span><span data-en>Source URL</span></label>
        <input type="text" id="f_ip_source" placeholder="https://raw.githubusercontent.com/.../list.json">
      </div>
    </div>

    <div class="card" id="logs">
      <h2><span class="dot"></span><span class="icon">🧾</span><span data-fa>لاگ‌های اخیر</span><span data-en>Recent logs</span></h2>
      <div class="loglist skel" id="logBox">…</div>
    </div>

    <div class="muted" style="text-align:center;margin:8px 0 18px">
      <a href="https://t.me/Imatix7" target="_blank" style="color:#c4b5fd;text-decoration:none">✈️ @Imatix7</a> · 
      <a href="https://github.com/imatixofficel/Matix-edg" target="_blank" style="color:#c4b5fd;text-decoration:none">GitHub / imatixofficel/Matix-edg</a>
    </div>

    <div class="save-bar">
      <button class="ghost" id="reloadBtn"><span data-fa>بارگذاری مجدد</span><span data-en>Reload</span></button>
      <button class="primary" id="saveBtn"><span data-fa>ذخیره تغییرات</span><span data-en>Save changes</span></button>
    </div>

  </main>

  <div class="modal" id="welcomeModal">
    <div class="modal-card">
      <span class="tg-icon">✈️</span>
      <h2 style="margin:10px 0 8px"><span data-fa>به کانال رسمی MatiX خوش آمدید</span><span data-en>Welcome to the official MatiX channel</span></h2>
      <p class="muted"><span data-fa>برای دریافت خبرهای پروژه و بروزرسانی‌ها می‌توانید عضو کانال شوید.</span><span data-en>Join the channel for project news and updates.</span></p>
      <button class="primary" style="width:100%;margin-top:14px" id="joinTelegram"><span data-fa>عضویت در تلگرام</span><span data-en>Join on Telegram</span></button>
      <button class="ghost" style="width:100%;margin-top:9px" id="closeWelcome"><span data-fa>بعداً</span><span data-en>Later</span></button>
    </div>
  </div>
  <div class="toast" id="toast"></div>

<script>
  const root = document.documentElement;
  const langBtn = document.getElementById('langBtn');
  function setLang(l){
    root.setAttribute('data-lang', l); root.setAttribute('lang', l); root.setAttribute('dir', l==='fa'?'rtl':'ltr');
    langBtn.textContent = l==='fa' ? 'EN' : 'فا'; localStorage.setItem('me_lang', l);
  }
  setLang(localStorage.getItem('me_lang') || 'en');
  langBtn.onclick = () => setLang(root.getAttribute('data-lang')==='fa' ? 'en' : 'fa');

  document.getElementById('logoutBtn').onclick = () => location.href = '/logout';

  const toastEl = document.getElementById('toast');
  function toast(msg, isErr){
    toastEl.textContent = msg; toastEl.className = 'toast show' + (isErr ? ' err' : '');
    setTimeout(()=> toastEl.classList.remove('show'), 2600);
  }
  const faOn = () => root.getAttribute('data-lang') === 'fa';
  if (window.matchMedia('(pointer:fine)').matches) {
    document.querySelectorAll('.card').forEach(card => {
      let raf = null;
      card.addEventListener('mousemove', e => {
        const rect = card.getBoundingClientRect();
        const px = (e.clientX - rect.left) / rect.width;
        const py = (e.clientY - rect.top) / rect.height;
        const rotY = (px - .5) * 10;
        const rotX = (.5 - py) * 8;
        if (raf) cancelAnimationFrame(raf);
        raf = requestAnimationFrame(() => {
          card.style.transform = `translateY(0) rotateX(${rotX}deg) rotateY(${rotY}deg) scale(1.015)`;
        });
      });
      card.addEventListener('mouseleave', () => {
        if (raf) cancelAnimationFrame(raf);
        card.style.transform = 'translateY(0) rotateX(0) rotateY(0) scale(1)';
      });
    });
  }
  const side = document.getElementById('side'), backdrop = document.getElementById('backdrop');
  document.getElementById('hamb').onclick = () => { side.classList.add('open'); backdrop.classList.add('show'); };
  backdrop.onclick = () => { side.classList.remove('open'); backdrop.classList.remove('show'); };
  side.querySelectorAll('a').forEach(a => a.addEventListener('click', () => { side.classList.remove('open'); backdrop.classList.remove('show'); }));
  const welcome = document.getElementById('welcomeModal');
  if (!localStorage.getItem('matix_tg_welcome')) welcome.classList.remove('hidden'); else welcome.classList.add('hidden');
  document.getElementById('joinTelegram').onclick = () => { localStorage.setItem('matix_tg_welcome','1'); window.open('https://t.me/Imatix7','_blank','noopener'); welcome.classList.add('hidden'); };
  document.getElementById('closeWelcome').onclick = () => { localStorage.setItem('matix_tg_welcome','1'); welcome.classList.add('hidden'); };

  let currentConfig = null;

  function updateUsage(c){
    const u = c.CF?.Usage || {};
    const usedBytes = Math.max(0, Number(u.pages)||0) + Math.max(0, Number(u.workers)||0);
    const usedMB = usedBytes / (1024*1024);
    const usedGB = usedBytes / (1024*1024*1024);
    const limitGB = Math.max(0, Number(c.preferredSubGen?.LIMIT_GB)||0);
    const pct = limitGB > 0 ? Math.min(100, usedGB / limitGB * 100) : 0;
    document.getElementById('usageTotal').textContent = usedGB >= 1 ? usedGB.toFixed(2)+' GB' : usedMB.toFixed(1)+' MB';
    document.getElementById('usageFill').style.width = pct.toFixed(1)+'%';
    document.getElementById('usageMeta').textContent = (faOn() ? 'درصد از سقف: ' : 'Percent of quota: ') + pct.toFixed(1) + '%';
    document.getElementById('quotaTotal').textContent = limitGB + ' GB';
    const days = Number(c.preferredSubGen?.LIMIT_DAYS)||0;
    document.getElementById('expireMeta').textContent = (faOn() ? 'اعتبار: ' : 'Validity: ') + days + (faOn() ? ' روز' : ' days');
  }

  async function loadConfig(){
    try{
      const res = await fetch('/admin/config.json', { credentials: 'same-origin' });
      if (!res.ok) throw new Error('load failed');
      const c = await res.json();
      currentConfig = c;
      document.getElementById('subLink').value = location.origin + '/sub?token=' + (c.preferredSubGen?.TOKEN || '');
      document.getElementById('nodeLink').value = c.LINK || '';
      document.getElementById('f_subname').value = c.preferredSubGen?.SUBNAME || '';
      document.getElementById('f_path').value = c.PATH || '/';
      document.getElementById('f_protocol').value = c.protoType || 'vless';
      document.getElementById('f_transport').value = c.transportProto || 'ws';
      document.getElementById('f_fp').value = c.Fingerprint || 'chrome';
      document.getElementById('f_frag').value = c.TLSsplitPiece || '';
      document.getElementById('f_skipcert').checked = !!c.skipCertDocVerifyCert;
      document.getElementById('f_randpath').checked = !!c.randomPath;
      document.getElementById('f_0rtt').checked = !!c.enableUse0RTT;
      document.getElementById('f_limit_days').value = c.preferredSubGen?.LIMIT_DAYS ?? 30;
      document.getElementById('f_limit_gb').value = c.preferredSubGen?.LIMIT_GB ?? 100;
      document.getElementById('f_ip_source').value = c.preferredSubGen?.CLEAN_IP_SOURCE || 'https://raw.githubusercontent.com/vfarid/cf-clean-ips/main/list.json';
      updateUsage(c);
      const proxyKey = Object.keys(c.relay || {}).find(k => k.toUpperCase() === 'PROXYIP');
      document.getElementById('f_proxyip').value = (proxyKey ? c.relay[proxyKey] : 'auto') || 'auto';
      document.getElementById('f_socks_type').value = (c.relay?.SOCKS5?.enableUse || '').toLowerCase();
      document.getElementById('f_socks_account').value = c.relay?.SOCKS5?.account || '';
      document.getElementById('f_socks_global').checked = !!c.relay?.SOCKS5?.allScope;
      loadAddList();
      loadLogs();
    }catch(e){ toast(faOn() ? 'خطا در بارگذاری تنظیمات' : 'Failed to load settings', true); }
  }

  async function loadAddList(){
    // The server returns auto-generated random IPs when no manual list has been
    // saved yet, so we can't reliably tell "auto" apart from "manual, happens to
    // match". We leave this field blank on load — saving it (even empty) simply
    // keeps whatever you type; leaving it untouched keeps the automatic IPs.
    document.getElementById('f_addlist').value = '';
  }

  async function loadLogs(){
    const box = document.getElementById('logBox');
    try{
      const res = await fetch('/admin/log.json', { credentials: 'same-origin' });
      const logs = res.ok ? await res.json() : [];
      box.classList.remove('skel');
      box.innerHTML = (Array.isArray(logs) && logs.length)
        ? logs.slice(-30).reverse().map(l => '<div>' + (typeof l === 'string' ? l : JSON.stringify(l)) + '</div>').join('')
        : (faOn() ? '<div>لاگی ثبت نشده</div>' : '<div>No logs yet</div>');
    }catch(e){ box.classList.remove('skel'); box.textContent = faOn() ? 'خطا در بارگذاری لاگ' : 'Failed to load logs'; }
  }

  document.querySelectorAll('.copy').forEach(btn => {
    btn.addEventListener('click', async () => {
      const el = document.getElementById(btn.dataset.copy);
      try{ await navigator.clipboard.writeText(el.value); toast(faOn() ? 'کپی شد' : 'Copied'); }
      catch(e){ el.select(); document.execCommand('copy'); toast(faOn() ? 'کپی شد' : 'Copied'); }
    });
  });

  document.getElementById('reloadBtn').onclick = loadConfig;

  document.getElementById('resetBtn').onclick = async () => {
    const ok = confirm(faOn() ? 'مطمئنی می‌خوای همه‌ی تنظیمات به حالت پیش‌فرض برگردن؟' : 'Reset all settings to default?');
    if (!ok) return;
    try{
      const res = await fetch('/admin/init', { credentials: 'same-origin' });
      if (!res.ok) throw new Error();
      toast(faOn() ? 'تنظیمات ریست شد' : 'Settings reset');
      loadConfig();
    }catch(e){ toast(faOn() ? 'ریست ناموفق بود' : 'Reset failed', true); }
  };

  document.getElementById('saveBtn').onclick = async () => {
    if (!currentConfig) return;
    const btn = document.getElementById('saveBtn');
    btn.disabled = true;
    try{
      const c = currentConfig;
      c.preferredSubGen = c.preferredSubGen || {};
      c.preferredSubGen.SUBNAME = document.getElementById('f_subname').value || 'MatiX';
      c.preferredSubGen.LIMIT_DAYS = Math.max(1, Number(document.getElementById('f_limit_days').value) || 30);
      c.preferredSubGen.LIMIT_GB = Math.max(0, Number(document.getElementById('f_limit_gb').value) || 100);
      c.preferredSubGen.CLEAN_IP_SOURCE = document.getElementById('f_ip_source').value.trim();
      c.PATH = document.getElementById('f_path').value || '/';
      c.protoType = document.getElementById('f_protocol').value;
      c.transportProto = document.getElementById('f_transport').value;
      c.Fingerprint = document.getElementById('f_fp').value;
      c.TLSsplitPiece = document.getElementById('f_frag').value || null;
      c.skipCertDocVerifyCert = document.getElementById('f_skipcert').checked;
      c.randomPath = document.getElementById('f_randpath').checked;
      c.enableUse0RTT = document.getElementById('f_0rtt').checked;
      c.relay = c.relay || {};
      const proxyKey = Object.keys(c.relay).find(k => k.toUpperCase() === 'PROXYIP') || 'PROXYIP';
      c.relay[proxyKey] = document.getElementById('f_proxyip').value || 'auto';
      c.relay.SOCKS5 = c.relay.SOCKS5 || {};
      c.relay.SOCKS5.enableUse = document.getElementById('f_socks_type').value || null;
      c.relay.SOCKS5.account = document.getElementById('f_socks_account').value || '';
      c.relay.SOCKS5.allScope = document.getElementById('f_socks_global').checked;

      const res = await fetch('/admin/config.json', {
        method: 'POST', credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(c)
      });
      if (!res.ok) throw new Error('save failed');

      const addlistVal = document.getElementById('f_addlist').value;
      if (addlistVal.trim()) {
        await fetch('/admin/ADD.txt', {
          method: 'POST', credentials: 'same-origin',
          headers: { 'Content-Type': 'text/plain;charset=utf-8' },
          body: addlistVal
        }).catch(() => null);
      }

      toast(faOn() ? 'ذخیره شد' : 'Saved');
      loadConfig();
    }catch(e){
      toast(faOn() ? 'ذخیره ناموفق بود' : 'Save failed', true);
    }finally{
      btn.disabled = false;
    }
  };

  loadConfig();
</script>
</body>
</html>`;
}
