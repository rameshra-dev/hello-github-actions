package panaces.agents.common.rlib;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Serializable;
import java.util.Date;
import java.util.Hashtable;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import panaces.agents.common.AgentCommons;
import panaces.agents.common.AgentContext;
import panaces.agents.common.AgentContextMap;
import panaces.agents.common.AgentContextNew;
import panaces.agents.common.CSAUtil;
import panaces.agents.common.CredStatus;
import panaces.agents.common.credhandler.CredHandler;
import panaces.agents.common.credhandler.CredHandlerImpl;
import panaces.agents.common.rlib.powershell.PowerShell;
import panaces.agents.common.rlib.powershell.PowerShellResponse;
import panaces.agents.services.ServMessages;
import panaces.common.CredPolicyIF;
import panaces.common.I18NUtil;
import panaces.common.cred.CredErrorCodes;
import panaces.common.exceptions.PanacesException;
import panaces.common.exceptions.PanacesIllegalArgumentException;
import panaces.common.model.cred.AccessProtocolWMI;
import panaces.common.model.cred.CredPolicy;
import panaces.common.model.cred.PwdCred;
import panaces.common.rexec.RExecAuthFailedException;
import panaces.common.rexec.RExecErrorCodes;
import panaces.common.rexec.RExecException;
import panaces.common.security.SecurityUtility;
import panaces.common.utils.FileUtil;
import panaces.common.utils.InstallUtil;
import panaces.common.utils.PanacesProcDetailsObject;
import panaces.common.utils.PanacesPropertyFileManager;
import panaces.common.utils.logger;

public class PowerShellSession implements ExecSession, Serializable {

	private static final int SUCCESS = 0;
	private static final int ACCESS_DENIED = 2;
	private static final int UNKNOWN_HOST = 8;
	private static final long serialVersionUID = 1L;
	private static final String PANACES_REMOTE_AGENTS_KEEP_TEMP_FILES = null;
	private String panace_property_file = InstallUtil.getConfigFileDir() + "panaces.properties";
	private String powerShellCred = "$mycred";
	private String newSession = " $Session"+System.currentTimeMillis();
	private String sessionString = " -Session "+newSession;
	private String subModule = "PSSession";
	private static CredHandler credHandler = AgentContext.getCredHandler();
	private static Hashtable<String, String> stageInPaths = new Hashtable<>();
	private String targetIpAddress;
	private CredStatus credStatus;
	private PwdCred authInfo = null;
	private PowerShell session = null;
	private String filePrefix="ro_remote_";
	private String domain;
	private String userName;
	private String passwd;
	private boolean connected = false;
	private static final String CRED_INITED_MSG = "$PSVersionTable";

	public PowerShellSession(String targetIpAddress, CredStatus credStatus) {
		this.targetIpAddress = targetIpAddress;
		this.credStatus = credStatus;
		CredPolicy credPolicy = credStatus.getCredPolicy();
		authInfo = (PwdCred) credPolicy.getCred();
	}
	
	public PowerShellSession(String targetIpAddress, WindowsPSCredentials psCreds) {
		this.targetIpAddress = targetIpAddress;
		authInfo = new PwdCred(psCreds.getUsername(), psCreds.getDomain(), psCreds.getUsername(), psCreds.getPassword());
	}


	@Override
	public synchronized void connect() throws PanacesException {
		if(!connected)
			_connect();
	}

	//TODO comment
	public synchronized PanacesProcDetailsObject exec(String powershellCommand) throws PanacesException {
		PanacesProcDetailsObject retObj = null;
		if(powershellCommand.contains(ExecSession.SESSION_FILTER))
			powershellCommand = powershellCommand.replace(ExecSession.SESSION_FILTER, sessionString);
		else
			powershellCommand += sessionString;
		long startTime = System.currentTimeMillis();
		PowerShellResponse response = session.executeCommand(powershellCommand);
		long endTime = System.currentTimeMillis();
		logger.print(logger.VERBOSE2, logger.AGENT, subModule, "TOTAL TIME TAKEN TO EXECUTE  PS COMMAND    --->  "+(endTime - startTime));
		logger.print(logger.VERBOSE2, logger.AGENT, subModule, "cmd-> " + powershellCommand);
		validateResponse(response);
		
		retObj = createResult(response);
		logger.print(logger.VERBOSE2, logger.AGENT, subModule, "RESPONSE FROM EXEC STRING   ---->   "+response.getCommandOutput());
		return retObj;
	}
	
	@Override
	public synchronized PanacesProcDetailsObject exec(ExecCommand cmd) throws PanacesException {
		logger.print(logger.VERBOSE2, logger.AGENT, subModule, "IN POWERSHELL ****** OLD EXEC METHOD WAS CALLED ...");
		File localTempFile = null;
		String cmdFile = null;
		try{
			long startTime = System.currentTimeMillis();
			cmdFile = filePrefix + new Date().getTime() + ".bat";
			logger.print(logger.VERBOSE2, logger.AGENT, subModule, "cmd-> " + cmd);
			
			String cmdString = buildCommandString(cmd);
			logger.print(logger.VERBOSE2, logger.AGENT, subModule, "COMMAND   ---->   "+cmdString);
			
			localTempFile = new File(cmdFile);
			witeCommandToFile(cmdString, localTempFile);
			
			remoteCopyCmdFile(localTempFile.getAbsolutePath(), cmdFile,null);
			
			//Execute the copy bat script
			PowerShellResponse response = session.executeCommand("Invoke-Command { "+getDestinationDir()+cmdFile+"} " +sessionString);
			long endTime = System.currentTimeMillis();
			logger.print(logger.VERBOSE2, logger.AGENT, subModule, "TOTAL TIME TAKEN TO EXECUTE  EXEC COMMAND    --->  "+(endTime - startTime));
			
			validateResponse(response);
			
			PanacesProcDetailsObject retObj = createResult(response);
			logger.print(logger.VERBOSE2, logger.AGENT, subModule, "RESPONSE FROM EXEC STRING   ---->   "+response.getCommandOutput());
			return retObj;	
		}finally{
			if(CSAUtil.deleteTempFiles()){
				FileUtil.deleteFile(localTempFile);
				//Remove the cmd file.
				removeFile(getDestinationDir()+cmdFile);
			}
		}
	}

	private PanacesProcDetailsObject createResult(PowerShellResponse response) throws RExecException {
		PanacesProcDetailsObject retObj = new PanacesProcDetailsObject();
		boolean rc = response.isError();
		if (rc) {
			logger.print(logger.ERROR, logger.AGENT, subModule, "rexec failed: rc = " + rc);
			 processErrorCode(ACCESS_DENIED);
		}else{
			retObj.setExitCode(SUCCESS);
			retObj.setSTDOut(response.getCommandOutput());
			retObj.setExecType(PanacesProcDetailsObject.EXEC_TYPE_CMD);
		}
		return retObj;
	}

	private void validateResponse(PowerShellResponse response) throws RExecException {
		if (response == null) {
			logger.print(logger.ERROR, logger.AGENT, subModule, "Failed to execute command:");
			throw new RExecException(RExecErrorCodes.rexecErr, new String[] { "Failed to execute command." },
					"RExec Failed: result is null");
		}else if(response.getCommandOutput() != null && 
				response.getCommandOutput().contains("not recognized as an internal or external command")){
			logger.print(logger.ERROR, logger.AGENT, subModule, "Failed to execute command with exception:");
			throw new RExecException(RExecErrorCodes.rexecErr, new String[] { response.getCommandOutput() },
					"RExec Failed: result is "+response.getCommandOutput());
			
		}else if(response.getCommandOutput() != null && 
				response.getCommandOutput().contains("WinRM cannot")){
			logger.print(logger.ERROR, logger.AGENT, subModule, "Failed to execute command with exception:");
			throw new RExecException(RExecErrorCodes.rexecErr, new String[] { response.getCommandOutput() },
					"RExec Failed: result is "+response.getCommandOutput());
			
		}else if(response.getCommandOutput() != null && 
				(response.getCommandOutput().contains("Cannot validate") || response.getCommandOutput().contains("argument is null or empty"))){
			logger.print(logger.ERROR, logger.AGENT, subModule, "Failed to execute command with exception:");
			throw new RExecException(RExecErrorCodes.rexecErr, new String[] { response.getCommandOutput() },
					"RExec Failed: result is "+response.getCommandOutput());
		}
	}

	private String buildCommandString(ExecCommand cmd) {
		String cmdString = cmd.getCmd();
		cmdString+=" ";
		
		List<Object> args = cmd.getArgs();
		if(null != args && args.size() > 0){
			for(int i = 0; i < args.size(); i++){
				String ar = (String) args.get(i);
				if(!"\"".equals(ar)){
					cmdString+=ar;
				cmdString+=" ";
				}
			}
		}
		return cmdString;
	}

	private void witeCommandToFile(String cmdString, File tempLocalFile) {
		logger.print(logger.VERBOSE2, logger.AGENT, subModule, "Local File created   -->  "+tempLocalFile.getAbsolutePath());
		FileWriter writer = null;
		try {
			writer = new FileWriter(tempLocalFile);
			writer.write("@echo off");
			writer.write(System.getProperty("line.separator"));
			char[] charArray = cmdString.toCharArray();
			for(char c : charArray){
				if(';' == c){
					if(cmdString.contains("select") || cmdString.contains("Select") || cmdString.contains("SELECT") || cmdString.contains("osql")){
						//DB commands, so ';' is required.
						writer.write(c);
					}
					else
						writer.write(System.getProperty("line.separator"));
				}
				else
					writer.write(c);
			}
		} catch (IOException e) {
			e.printStackTrace();
		}finally{
			if(null != writer){
				try {
					writer.close();
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
		}
	}
	
	private void processErrorCode(int rc) throws RExecException {
		switch (rc) {
		case 2: throw new RExecException(RExecErrorCodes.rexecErr, new String [] {"Access Denied"}, null);
		case 3: throw new RExecException(RExecErrorCodes.rexecErr, new String [] {"Insufficient Priviledge"}, null);
		case 8: throw new RExecException(RExecErrorCodes.rexecErr, new String [] {"Unknown failure"}, null);
		case 9: throw new RExecException(RExecErrorCodes.rexecErr, new String [] {"Path Not Found"}, null);
		case 21: throw new RExecException(RExecErrorCodes.rexecErr, new String [] {"Invalid Parameter"}, null);
		}
	}
	private void removeFile(String filePath){
		try{
			PowerShellResponse response = session.executeCommand("Invoke-Command {Remove-Item -Path "+filePath+"} -Session "+newSession);
			if(response == null){
				//ERROR - TODO
				System.out.println("Response is null something wrong");
				//loogger.
			}
		}catch (Exception e) {
			// TODO: handle exception
		}
		
	}

	@Override
	public PanacesProcDetailsObject shellexec(ExecCommand cmd) throws PanacesException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void close() {
		if(null != session){
			session.executeCommand("Remove-PSSession "+newSession);
			session.close();
		}
	}

	@Override
	public int status() throws PanacesException {
		logger.print(logger.VERBOSE2, logger.AGENT, subModule, "SESSION VALUE  -->  "+session);
		if(null != session){
			PanacesProcDetailsObject output = exec("Invoke-Command { Test-Path  'C:\\' } ");
			if(null != output && null != output.getSTDOut()&& "True".equalsIgnoreCase(output.getSTDOut().trim())){
				return 1;
			}
		}
		return 0;
	}

	@Override
	public boolean ping() throws PanacesException {
		AgentContextNew agn=AgentContextMap.getAgentContextFromIP(targetIpAddress);
		if (!agn.isTargetHostReady()) {
			return false;
		}

		AccessProtocolWMI apWMI = (AccessProtocolWMI) credStatus.getCredPolicy().getAccessProtocol();
		int port = apWMI.getPort();

		// using simple socket connection to verify if port 135 is up or not.
		if (AgentCommons.ping(targetIpAddress, port)) {
			agn.setTargetHostAccessible();
			return true;
		} else {
			agn.setTargetHostNotAccessible();
			return false;
		}
	}

	@Override
	public void initiateSftpClient() throws PanacesException {
		// TODO Auto-generated method stub

	}

	private void _connect() throws PanacesException {
		logger.print(logger.VERBOSE, logger.AGENT, subModule, "credhandler from the Agentcontext is  " + credHandler);
		AgentContextNew agn = AgentContextMap.getAgentContextFromIP(targetIpAddress);
		if(null != credStatus){
			CredPolicy cp = credStatus.getCredPolicy();
			
			logger.print(logger.VERBOSE, logger.AGENT, subModule, "Bypass Locking : " + cp.byPassLocking());
			authInfo = (PwdCred) cp.getCredPolicy().getCred();
			if (null == credHandler) {
				logger.print(logger.WARNING, logger.AGENT, subModule,
						"credHandler is null so initializing it, this should not happen");
				credHandler = new CredHandlerImpl();
				agn.setCredHandler(credHandler);
			}
			
			// Locking is bypassed for test cred functionality
			if (!cp.byPassLocking()) {
				logger.print(logger.VERBOSE, logger.AGENT, subModule, "Verifying the Credentials " + cp);
				if(agn != null){
				if (credHandler.keyExists(cp.getObjectIdentifier(),agn)) {
					try {
						// this is a blocking call.
						// it will resume once Agent gets new cred from DRM.
						CredPolicyIF newCred = credHandler.getCredWithAgentContext(cp.getObjectIdentifier(),agn);
						logger.print(logger.VERBOSE, logger.AGENT, subModule, "Got new credentials for " + cp);
						if (newCred != null) {
							authInfo = (PwdCred) newCred.getCredPolicy().getCred();
							//this.credStatus.setCredSuccess();
						} else {
							throw new PanacesIllegalArgumentException(CredErrorCodes.NoCredPolicyFound, null,
									"Received null cred from credHandler for " + cp.getObjectIdentifier());
						}
					} catch (Exception e) {
						throw new PanacesException(CredErrorCodes.NoCredPolicyFound, null, e.getMessage());
					}
				}
			} 
			}
			
			if (authInfo.getPassword() == null) {
				String msg = "Password is not available. If using vault, please check vault configuration.";
				credStatus.setCredStatusFailed(
						"ipaddress = " + targetIpAddress + ", user = " + authInfo.getUsername() + " : " + msg);
				logger.print(logger.ERROR, logger.AGENT, subModule, msg);
				
				logger.print(logger.ERROR, logger.AGENT, subModule,
						"Locking: " + msg + " .setting the cred as expired for cred " + cp);
				   if(agn == null){
					     setExpired(cp);
					     }else{
					    	 setExpiredWithAgentContext(cp,agn); 
					     }
				throw new RExecAuthFailedException(RExecErrorCodes.rexecAuthFailure,
						new String[] {
								"ipaddress = " + targetIpAddress + ", user = " + authInfo.getUsername() + ": " + msg },
						msg);
			}
		}


		userName = authInfo.getUsername();
		domain = authInfo.getDomain();
		if (domain == null || domain.trim().length() == 0) {
			domain = targetIpAddress;
		}

		logger.print(logger.VERBOSE, logger.AGENT, subModule,
				"_connect :: going to decrypt the pwd and making connection");
		try {
			// Decrypting the password before connection
			passwd = authInfo.getPassword();
			try {
				passwd = SecurityUtility.decrypt(passwd);
			}catch (Exception e) {
				logger.print(logger.VERBOSE, logger.AGENT, subModule,
						"_connect :: decryption failed one case may be because we are calling junits");
			}
			passwd = passwd.trim();
			passwd = escapeSpecialChars(passwd);
			String newUserName = domain +"\\"+userName.trim();
			targetIpAddress = targetIpAddress.trim();
			session = PowerShell.openSession();
			// Execute a light weight command to validate credentials.
			String creds = "$PlainPassword =\"" + passwd
					+ "\";$SecurePassword=$PlainPassword | ConvertTo-SecureString -AsPlainText -Force;"
					+ powerShellCred +" =new-object -typename System.Management.Automation.PSCredential(\"" + newUserName
					+ "\", $SecurePassword);";

			session.executeCommand(creds);
			PowerShellResponse response = session.executeCommand(newSession+" = new-PSSession -ComputerName " + targetIpAddress + " -Credential " + powerShellCred);
			logger.print(logger.VERBOSE, logger.AGENT, subModule, "Remote Session Created with Name  -->  "+newSession);
			String cmdOutput = ""+response.getCommandOutput();
			logger.print(logger.VERBOSE, logger.AGENT, subModule, "PowerShellResponse obj is  -->  "+response.toString());
//			response = session.executeCommand(creds+" Invoke-Command { Test-Path -Path 'C:\\' -PathType Container} -Session "+newSession );
//			String cmdOutput = ""+response.getCommandOutput();
			logger.print(logger.INFO, logger.AGENT, subModule, "Command Output  -->  "+cmdOutput);
			
			if(I18NUtil.contains(cmdOutput, ServMessages.getMessage("POWERSHELL_ACCESS_IS_DENIED"))){
				logger.print(logger.VERBOSE, logger.AGENT, subModule, "ACCESS IS DENIED  !!");
				setFailedCredStatus("Access is denied. ipaddress = " + targetIpAddress + ", user = " + authInfo.getUsername(),agn);
				if(null != credStatus){
					CredPolicy cp = credStatus.getCredPolicy();
				if(agn == null){
				     setExpired(cp);
				     }else{
				    	 setExpiredWithAgentContext(cp,agn); 
				     }
				}
				logger.print(logger.ERROR, logger.AGENT, subModule, "Error in Command Output  -->  "+cmdOutput);
				throw new RExecAuthFailedException(RExecErrorCodes.rexecAuthFailure,
			    		 new String [] {"ipaddress = "  +  targetIpAddress +
			    		 ", user = " +  authInfo.getUsername() + ", " + "Access is denied, cred not correct or no administrator privileges."}, "Access Denied");
			}else if(I18NUtil.contains(cmdOutput, ServMessages.getMessage("POWERSHELL_UNABLE_TO_CONNECT"))){
				logger.print(logger.VERBOSE, logger.AGENT, subModule, "UNKNOWN HOST  !!");
				setFailedCredStatus("Unknown host: "+targetIpAddress,agn);
				if(null != credStatus){
					CredPolicy cp = credStatus.getCredPolicy();
				if(agn == null){
				     setExpired(cp);
				     }else{
				    	 setExpiredWithAgentContext(cp,agn); 
				     }
				}
				throw new RExecException(RExecErrorCodes.unknownHost, new String [] {targetIpAddress, "Host Unreachable"}, "Host Unreachavle");
			}else if (I18NUtil.contains(cmdOutput, "computer is accessible")) {
                logger.print(logger.VERBOSE, logger.AGENT, subModule, "COMPUTER NOT ACCESSIBLE  !!");
                setFailedCredStatus("Unknown host: "+targetIpAddress,agn);
                if(null != credStatus){
                        CredPolicy cp = credStatus.getCredPolicy();
                if(agn == null){
                     setExpired(cp);
                     }else{
                         setExpiredWithAgentContext(cp,agn);
                     }
                }
                throw new RExecException(RExecErrorCodes.unknownHost, new String [] {targetIpAddress, "Computer not reachable"}, "Host Unreachavle");
			} else if (I18NUtil.contains(cmdOutput, "Use winrm.cmd to configure TrustedHosts")) {
                logger.print(logger.VERBOSE, logger.AGENT, subModule, "COMPUTER NOT ACCESSIBLE - TrustedHosts !!");
                setFailedCredStatus("Unknown host: "+targetIpAddress,agn);
                if(null != credStatus){
                        CredPolicy cp = credStatus.getCredPolicy();
                if(agn == null){
                     setExpired(cp);
                     }else{
                         setExpiredWithAgentContext(cp,agn);
                     }
                }
                throw new RExecException(RExecErrorCodes.unknownHost, new String [] {targetIpAddress, "Computer not reachable"}, "Host Unreachavle");
			}
			if (!response.isError()) {
				logger.print(logger.VERBOSE, logger.AGENT, subModule, "POWERSHELL CALL IS SUCCESSFUL !!");
				agn.setTargetHostAccessible();
				connected = true;
				if(null != credStatus)
					credStatus.setCredSuccess();
			}
		}
		catch (Exception e) {
			connected = false;
			logger.print(logger.ERROR, logger.AGENT, subModule, e.toString());
			throw new RExecException(RExecErrorCodes.rexecConnectFailure,
			    	 new String [] {targetIpAddress, e.getMessage()}, e.getMessage(), e);
		}
	}

	private String escapeSpecialChars(String passwd2) {
		if (passwd2 == null)
			return passwd2;

		// First escape ` by adding extra `
		passwd2 = passwd2.replaceAll("`", "``");

		// Escape $ with `$
		passwd2 = passwd2.replaceAll("\\$", "`\\$");

		// Escape " with `"
		passwd2 = passwd2.replaceAll("\"", "`\"");

		return passwd2;
	}

	private void setFailedCredStatus(String statusMsg,AgentContextNew agn){
		agn.setTargetHostNotAccessible();
		credStatus.setCredStatusFailed(statusMsg);
	}

	private void setExpired(CredPolicy cp) {
		if (!cp.byPassLocking()) {
			credHandler.setExpired(cp.getObjectIdentifier());
		}
	}
	
	private void setExpiredWithAgentContext(CredPolicy cp,AgentContextNew agn) {
		if(! cp.byPassLocking()){
			credHandler.setExpiredWithAgentContext(cp.getObjectIdentifier(),agn);
		}
	}

	public int remoteCopyCmdFile(String cmdFile, String filename, String destination) {
		logger.print(logger.VERBOSE2, logger.AGENT, subModule, "command file  -->  "+cmdFile+"  File Name  ::  "+filename + "  Destination   --> "+destination);
		logger.print(logger.VERBOSE2, logger.AGENT, subModule, "Target IP  --> "+targetIpAddress+"  UserName  -->  "+userName);
		// write file for running command
		String dest = getDestinationDir();
		if(null != destination && destination.length() != 0 && ! destination.endsWith("\\")){
				dest = destination.concat("\\");			
		}
		// Copy Command File.
		String fileReadCmd = "$File = [System.IO.File]::ReadAllBytes(\"" + cmdFile + "\")";
		PowerShellResponse response = session.executeCommand(fileReadCmd);
		logger.print(logger.VERBOSE, logger.AGENT, subModule, "File Data Read Command  -->  "+fileReadCmd);
		String fileWriteCmd = "Invoke-Command "+sessionString+" -ArgumentList $File -ScriptBlock {[System.IO.File]::WriteAllBytes( \""
						+ dest + filename + "\", $args)} ";
		response = session.executeCommand(fileWriteCmd);
		logger.print(logger.VERBOSE2, logger.AGENT, subModule, "Remote File Copy Command  ----->  "+ fileWriteCmd);
		String cmdOutput = response.getCommandOutput();
		if(cmdOutput.contains("Access is denied.")){
			logger.print(logger.VERBOSE2, logger.AGENT, subModule, "ACCESS IS DENIED  !!");
			return ACCESS_DENIED;
		}else if(cmdOutput.contains("The WinRM client cannot process the request because the server name cannot be resolved.")){
			logger.print(logger.VERBOSE2, logger.AGENT, subModule, "UNKNOWN HOST  !!");
			return UNKNOWN_HOST;
		}else if(cmdOutput.contains("WinRM cannot")){
			logger.print(logger.VERBOSE2, logger.AGENT, subModule, "UNKNOWN HOST - server not reachable !!");
			return UNKNOWN_HOST;
		}
		if (!response.isError()) {
			logger.print(logger.VERBOSE2, logger.AGENT, subModule, "POWERSHELL CALL IS SUCCESSFUL !!");
			return SUCCESS;
		}
		return UNKNOWN_HOST;
	}

	private String getDestinationDir() {
		String stageinPath = stageInPaths.get(targetIpAddress);
		if (null != stageinPath && stageinPath.trim().length() > 0) {
			logger.print(logger.VERBOSE2, logger.AGENT, subModule,
					"Stage in path calculated earlier --> " + stageinPath);
			return stageinPath;
		}
		try {
			PanacesPropertyFileManager fileManager = new PanacesPropertyFileManager(panace_property_file);
			Hashtable<String, String> properties = fileManager.getProperties();
			String val = properties.get("powershell.endpoint.tempfile.creation.path");
			PanacesProcDetailsObject output = exec("Invoke-Command { Test-Path  '" + val + "' }");
			if (null != output && null != output.getSTDOut() && "True".equalsIgnoreCase(output.getSTDOut().trim())) {
				logger.print(logger.VERBOSE2, logger.AGENT, subModule, "Stage in path present --> " + val);
				stageInPaths.put(targetIpAddress, val);
				return val;
			} else {
				logger.print(logger.VERBOSE, logger.AGENT, subModule, "Stage in path is not present in sub-system");
			}
		} catch (FileNotFoundException e) {
			logger.printStackTrace(logger.AGENT, subModule, e);
		} catch (IOException e) {
			logger.printStackTrace(logger.AGENT, subModule, e);
		} catch (PanacesException e) {
			logger.printStackTrace(logger.AGENT, subModule, e);
		}

		/*
		 * If control comes here it means, the path configured in Sitecontroller is not
		 * present in the sub-system, for which exception is logged. Now we will look
		 * for the temp location in the sub-system and return it. If the temp is not
		 * present we will return C:\.
		 */
		try {
			PanacesProcDetailsObject output = exec("Invoke-Command { CMD.exe /c set temp }");
			if (null != output && null != output.getSTDOut()) {
				String val = output.getSTDOut();
				if (null != val && val.trim().length() > 0) {
					logger.print(logger.VERBOSE2, logger.AGENT, subModule, "GOT THE TEMP DIR  --> " + val);
					stageInPaths.put(targetIpAddress, val);
					return val;
				} else {
					logger.print(logger.VERBOSE, logger.AGENT, subModule,
							"No temp dir configured or removed from environment entry ...");
				}
			}
		} catch (PanacesException e) {
			logger.printStackTrace(logger.AGENT, subModule, e);
		}
		stageInPaths.put(targetIpAddress, "C:\\");
		return "C:\\";
	}
	
	@Override
	public boolean equals(Object obj) {
		if (this == obj){
			logger.print(logger.VERBOSE2, logger.AGENT, subModule, "--------------------------1-------------------------" );
			return true;
		}
		if (obj == null){
			logger.print(logger.VERBOSE2, logger.AGENT, subModule, "--------------------------2-------------------------" );
			return false;
		}
		if (getClass() != obj.getClass()){
			logger.print(logger.VERBOSE2, logger.AGENT, subModule, "--------------------------3-------------------------" );			
			return false;
		}
		PowerShellSession other = (PowerShellSession) obj;
		if (this.credStatus == null) {
			logger.print(logger.VERBOSE2, logger.AGENT, subModule, "CREDSTATUS is NULL for this object"+this );
			if (other.credStatus != null){
				logger.print(logger.VERBOSE2, logger.AGENT, subModule, "--------------------------4-------------------------" );
				return false;
			}
			logger.print(logger.VERBOSE2, logger.AGENT, subModule, "CREDSTATUS is also Null for other object-> " + other);
		} else if(null != this.credStatus && null != other.credStatus){
			CredPolicy credPolicy = this.credStatus.getCredPolicy();
			CredPolicy otherCredPol = other.credStatus.getCredPolicy();
			if(credPolicy == null && otherCredPol != null){
				logger.print(logger.VERBOSE2, logger.AGENT, subModule, "this.credpolicy = null but other.credpolicy is not null " + otherCredPol);
				logger.print(logger.VERBOSE2, logger.AGENT, subModule, "--------------------------5-------------------------" );
				return false;
			}
			else if(credPolicy != null && otherCredPol == null){
				logger.print(logger.VERBOSE2, logger.AGENT, subModule, "this.credpolicy is not null but other.credpolicy is null " + credPolicy);
				logger.print(logger.VERBOSE2, logger.AGENT, subModule, "--------------------------6-------------------------" );
				return false;
			}
			else if(credPolicy != null && otherCredPol != null){
				String un1 = credPolicy.getUserName();
				String pw1 =credPolicy.getPassword();
				pw1=SecurityUtility.decrypt(pw1);
				String un2 = otherCredPol.getUserName();
				String pw2 =otherCredPol.getPassword();
				pw2 = SecurityUtility.decrypt(pw2);
				logger.print(logger.VERBOSE2, logger.AGENT, subModule, "this.userName  -->  "+un1);
				logger.print(logger.VERBOSE2, logger.AGENT, subModule, "other.userName  -->  "+un2);
				if(un1 == null && un2 != null)
					return false;
				else if(un1 != null && un2 == null)
					return false;
				else if(!un1.trim().equals(un2.trim()))
					return false;
				
				if(pw1 == null && pw2 != null){
					logger.print(logger.VERBOSE2, logger.AGENT, subModule, "--------------------------7-------------------------" );					
					return false;
				}
				else if(pw1 != null && pw2 == null){
					logger.print(logger.VERBOSE2, logger.AGENT, subModule, "--------------------------8-------------------------" );					
					return false;
				}
				else if(!pw1.trim().equals(pw2.trim())){
					logger.print(logger.VERBOSE2, logger.AGENT, subModule, "--------------------------9-------------------------" );					
					return false;
				}
			}
		}
		logger.print(logger.VERBOSE2, logger.AGENT, subModule, "this.targetIP  -->  "+targetIpAddress);
		logger.print(logger.VERBOSE2, logger.AGENT, subModule, "other.targetIP  -->  "+other.targetIpAddress);
		if (targetIpAddress == null) {
			if (other.targetIpAddress != null){
				logger.print(logger.VERBOSE2, logger.AGENT, subModule, "--------------------------10-------------------------" );
				return false;
			}
		} else if (!targetIpAddress.equals(other.targetIpAddress)){
			logger.print(logger.VERBOSE2, logger.AGENT, subModule, "--------------------------11-------------------------" );
			return false;
		}
		logger.print(logger.VERBOSE2, logger.AGENT, subModule, "--------------------------12-------------------------" );
		return true;
	}

	@Override
	public synchronized PanacesProcDetailsObject execNew(ExecCommand cmd) throws PanacesException {
		logger.print(logger.VERBOSE2, logger.AGENT, subModule, "IN POWERSHELL NEW EXEC METHOD WAS CALLED ...");
		if(null != cmd) {
			String execCmd = cmd.toCmdLineString();
			/*
			 * more specific regex used. The command submitted if it starts with single or
			 * multiple spaces and after that if it contains "&" char and then one or more
			 * space than only the condition matches.
			 */
			String regex = "^\\s+&\\s+";
			Pattern pattern = Pattern.compile(regex, Pattern.CASE_INSENSITIVE);
			Matcher matcher = pattern.matcher(execCmd);
			if (matcher.find()) {
				
				/**
				 * <pre>
				 * Example if {[isWin] == 1 } { lappend command
				 * " & \"$DRServiceTDPSQLCPath\" restore $MSSQLDBName full /object=$fullBkpObjId /Recovery=$recoveryFlag /replace /sqluser=$MSSQLDBUserName /sqlpassword=$MSSQLDBPassword /tsmoptfile=\"$DRServiceOPTFilePath\" /tsmpassword=$nodePassword"
				 * } else { lappend command
				 * " \"$DRServiceTDPSQLCPath\" restore $MSSQLDBName full /object=$fullBkpObjId /Recovery=$recoveryFlag /replace /sqluser=$MSSQLDBUserName /sqlpassword=$MSSQLDBPassword /tsmoptfile=\"$DRServiceOPTFilePath\" /tsmpassword=$nodePassword"
				 * } 
				 * 
				 * Basically if the cmd is going to execute on windows and sent to
				 * PowershellSession class.
				 * 
				 * Now earlier when we are creating a file this
				 * \"$DRServiceTDPSQLCPath\" will be coming as "C://abc//df//some.exe"
				 * the \ will be escaped, but now since we are not creating file, 
				 * and executing the command this \ is coming, because of which the cmd is failing. 
				 * So this line --> execCmd = execCmd.replaceAll("\\\\", "");
				 * 
				 * Now the second execCmd = execCmd.replaceAll("/+", "/"); it for replacing
				 * multiple of // to one /.
				 * 
				 An example can be below 
				 
				 public static void main(String[] args) { 
					  String a = "\\\\\\\\\\ sambit\\//////MISTRA \\\\\\\\\\"; 
					  System.out.println(a); 
					  a = a.replaceAll("\\\\", ""); 
					  System.out.println(a); 
					  a = a.replaceAll("/+", "/");
					  System.out.println(a); 
				 }
				 
				 
				 * when this code runs output came as - 
				 * 
				 * \\\\\ sambit\//////MISTRA \\\\\
				 * sambit//////MISTRA 
				 * sambit/MISTRA
				 * </pre>
				 */
				execCmd = execCmd.replaceAll("\\\\", "");
				execCmd = execCmd.replaceAll("/+", "/");
				execCmd = "Invoke-Command { " + execCmd + " }";
			} else {
				execCmd = "Invoke-Command { CMD.exe /c " + execCmd + " }";
			}
			return exec(execCmd);
		}
		return null;
	}
	
	
	@Override
	public synchronized void testCreds() throws PanacesException {
		if(!connected)
			_testCreds();
	}
	
	
	private void _testCreds() throws PanacesException {
		try {
			AgentContextNew agn = AgentContextMap.getAgentContextFromIP(targetIpAddress);
			authInfo = getAuthInfo(agn);
			userName = authInfo.getUsername();
			domain = authInfo.getDomain();
			if (domain == null || domain.trim().length() == 0) {
				domain = targetIpAddress;
			}
	
			logger.print(logger.VERBOSE, logger.AGENT, subModule,
					"_connect :: going to decrypt the pwd and making connection");
			
				// Decrypting the password before connection
			passwd = authInfo.getPassword();
			try {
				passwd = SecurityUtility.decrypt(passwd);
			}catch (Exception e) {
				logger.print(logger.VERBOSE, logger.AGENT, subModule,
						"_connect :: decryption failed one case may be because we are calling junits");
			}
			passwd = passwd.trim();
			passwd = escapeSpecialChars(passwd);
			String newUserName = domain +"\\"+userName.trim();
			targetIpAddress = targetIpAddress.trim();
			session = PowerShell.openSession();
			
			String creds = "$PlainPassword =\"" + passwd
					+ "\";$SecurePassword=$PlainPassword | ConvertTo-SecureString -AsPlainText -Force;"
					+ powerShellCred +" =new-object -typename System.Management.Automation.PSCredential(\"" + newUserName
					+ "\", $SecurePassword);" +  newSession +" = new-PSSession -ComputerName " + targetIpAddress + " -Credential " + powerShellCred + ";" + CRED_INITED_MSG;

			PowerShellResponse response = session.executeCommand(creds);
			logger.print(logger.VERBOSE, logger.AGENT, subModule, "Remote Session Created for test creds with Name  -->  "+newSession);
			String cmdOutput = ""+response.getCommandOutput();
			logger.print(logger.VERBOSE, logger.AGENT, subModule, "PowerShellResponse obj is  -->  "+response.toString());
			logger.print(logger.INFO, logger.AGENT, subModule, "Command Output  -->  "+cmdOutput);
			processCmdOutput(response, cmdOutput, agn);
			
		}
		catch (Exception e) {
			connected = false;
			logger.print(logger.ERROR, logger.AGENT, subModule, e.toString());
			throw new RExecException(RExecErrorCodes.rexecConnectFailure,
			    	 new String [] {targetIpAddress, e.getMessage()}, e.getMessage(), e);
		}
	}
	
	
	private void processCmdOutput(PowerShellResponse response, String cmdOutput, AgentContextNew agn) throws PanacesException {
		if(I18NUtil.contains(cmdOutput, ServMessages.getMessage("POWERSHELL_ACCESS_IS_DENIED"))){
			logger.print(logger.VERBOSE, logger.AGENT, subModule, "ACCESS IS DENIED  !!");
			setFailedCredStatus("Access is denied. ipaddress = " + targetIpAddress + ", user = " + authInfo.getUsername(),agn);
			if(null != credStatus){
				CredPolicy cp = credStatus.getCredPolicy();
			if(agn == null){
			     setExpired(cp);
			     }else{
			    	 setExpiredWithAgentContext(cp,agn); 
			     }
			}
			logger.print(logger.ERROR, logger.AGENT, subModule, "Error in Command Output  -->  "+cmdOutput);
			throw new RExecAuthFailedException(RExecErrorCodes.rexecAuthFailure,
		    		 new String [] {"ipaddress = "  +  targetIpAddress +
		    		 ", user = " +  authInfo.getUsername() + ", " + "Access is denied, cred not correct or no administrator privileges."}, "Access Denied");
		}else if(I18NUtil.contains(cmdOutput, ServMessages.getMessage("POWERSHELL_UNABLE_TO_CONNECT"))){
			logger.print(logger.VERBOSE, logger.AGENT, subModule, "UNKNOWN HOST  !!");
			setFailedCredStatus("Unknown host: "+targetIpAddress,agn);
			if(null != credStatus){
				CredPolicy cp = credStatus.getCredPolicy();
			if(agn == null){
			     setExpired(cp);
			     }else{
			    	 setExpiredWithAgentContext(cp,agn); 
			     }
			}
			throw new RExecException(RExecErrorCodes.unknownHost, new String [] {targetIpAddress, "Host Unreachable"}, "Host Unreachavle");
		}else if (I18NUtil.contains(cmdOutput, "computer is accessible")) {
            logger.print(logger.VERBOSE, logger.AGENT, subModule, "COMPUTER NOT ACCESSIBLE  !!");
            setFailedCredStatus("Unknown host: "+targetIpAddress,agn);
            if(null != credStatus){
                    CredPolicy cp = credStatus.getCredPolicy();
            if(agn == null){
                 setExpired(cp);
                 }else{
                     setExpiredWithAgentContext(cp,agn);
                 }
            }
            throw new RExecException(RExecErrorCodes.unknownHost, new String [] {targetIpAddress, "Computer not reachable"}, "Host Unreachavle");
		} else if (I18NUtil.contains(cmdOutput, "Use winrm.cmd to configure TrustedHosts")) {
            logger.print(logger.VERBOSE, logger.AGENT, subModule, "COMPUTER NOT ACCESSIBLE - TrustedHosts !!");
            setFailedCredStatus("Unknown host: "+targetIpAddress,agn);
            if(null != credStatus){
                    CredPolicy cp = credStatus.getCredPolicy();
            if(agn == null){
                 setExpired(cp);
                 }else{
                     setExpiredWithAgentContext(cp,agn);
                 }
            }
            throw new RExecException(RExecErrorCodes.unknownHost, new String [] {targetIpAddress, "Computer not reachable"}, "Host Unreachavle");
		}
		if (!response.isError()) {
			logger.print(logger.VERBOSE, logger.AGENT, subModule, "POWERSHELL CALL IS SUCCESSFUL !!");
			agn.setTargetHostAccessible();
			connected = true;
			if(null != credStatus)
				credStatus.setCredSuccess();
		}
		
	}

	private PwdCred getAuthInfo(AgentContextNew agn) throws PanacesException {
		logger.print(logger.VERBOSE, logger.AGENT, subModule, "credhandler from the Agentcontext is  " + credHandler);
		agn = AgentContextMap.getAgentContextFromIP(targetIpAddress);
		if(null != credStatus){
			CredPolicy cp = credStatus.getCredPolicy();
			
			logger.print(logger.VERBOSE, logger.AGENT, subModule, "Bypass Locking : " + cp.byPassLocking());
			authInfo = (PwdCred) cp.getCredPolicy().getCred();
			if (null == credHandler) {
				logger.print(logger.WARNING, logger.AGENT, subModule,
						"credHandler is null so initializing it, this should not happen");
				credHandler = new CredHandlerImpl();
				agn.setCredHandler(credHandler);
			}
			
			// Locking is bypassed for test cred functionality
			if (!cp.byPassLocking()) {
				logger.print(logger.VERBOSE, logger.AGENT, subModule, "Verifying the Credentials " + cp);
				if(agn != null){
				if (credHandler.keyExists(cp.getObjectIdentifier(),agn)) {
					try {
						// this is a blocking call.
						// it will resume once Agent gets new cred from DRM.
						CredPolicyIF newCred = credHandler.getCredWithAgentContext(cp.getObjectIdentifier(),agn);
						logger.print(logger.VERBOSE, logger.AGENT, subModule, "Got new credentials for " + cp);
						if (newCred != null) {
							authInfo = (PwdCred) newCred.getCredPolicy().getCred();
							//this.credStatus.setCredSuccess();
						} else {
							throw new PanacesIllegalArgumentException(CredErrorCodes.NoCredPolicyFound, null,
									"Received null cred from credHandler for " + cp.getObjectIdentifier());
						}
					} catch (Exception e) {
						throw new PanacesException(CredErrorCodes.NoCredPolicyFound, null, e.getMessage());
					}
				}
			} 
			}
			
			if (authInfo.getPassword() == null) {
				String msg = "Password is not available. If using vault, please check vault configuration.";
				credStatus.setCredStatusFailed(
						"ipaddress = " + targetIpAddress + ", user = " + authInfo.getUsername() + " : " + msg);
				logger.print(logger.ERROR, logger.AGENT, subModule, msg);
				
				logger.print(logger.ERROR, logger.AGENT, subModule,
						"Locking: " + msg + " .setting the cred as expired for cred " + cp);
				   if(agn == null){
					     setExpired(cp);
					     }else{
					    	 setExpiredWithAgentContext(cp,agn); 
					     }
				throw new RExecAuthFailedException(RExecErrorCodes.rexecAuthFailure,
						new String[] {
								"ipaddress = " + targetIpAddress + ", user = " + authInfo.getUsername() + ": " + msg },
						msg);
			}
		}
		return authInfo;
	}
}