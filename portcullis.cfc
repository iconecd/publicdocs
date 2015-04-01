<cfcomponent output="false">

	<!---
		Portcullis is a CFC based url,form,cookie filter to help protect against
		SQL Injection and XSS scripting attacks.

		Author: John Mason, mason@fusionlink.com
		Blog: www.codfusion.com
		Twitter: john_mason_
		Public Version: 2.0.1
		Release Date: 4/23/2008
		Last Updated: 1/16/2010

		WARNING: URL, SQL Injection and XSS attacks are an ever evolving threats. Though this
		CFC will filter many types of attacks. There are no warranties, expressed or implied,
		with using this filter. It is YOUR responsibility to monitor/modify/update/alter this code
		to properly protect your application now and in the future. It is also highly encouraged to
		implement a hardware Web Application Firewall (WAF) to obtain the best protection. In fact,
		PCI-DSS requires either a full code audit or a WAF when handling credit card information.

		1.0.2 (4/23/2008) - First public release
		1.0.3 (5/10/2008) - Added CRLF defense, HttpOnly for cookies, remove individual IPs from the log and a new escapeChars function that replaces htmlEditFormat()
		1.0.4 (6/19/2008) - Fixed item naming with a regex scan to allow just alphanumeric and underscore characters
		1.0.5 (7/21/2008) - Added some key words to block the popular CAST()/ASCII injection attack. Also, fixed a bug reported if ampersands are in the url string it sometimes mixes up the variable naming
		1.0.6 (8/26/2008) - Exception field corrections, fixed a couple missing var scopes, querynew bug in CF6, bug fix for checkReferer
		1.0.7 (6/10/2009) - Added to sql and word filters, modified MSWord smart quotes filter
		2.0.0 (1/4/2010)  - Additions to the keyword list, accessors, context aware sql command words search
		2.0.1 (1/16/2010) - New isDetected() method and verification of valid variable names in accordance with the cf variable naming rules

		Follow me on Twitter to get Portcullis news - @john_mason_

		Special Thanks to Shawn Gorrell who developed the XSSBlock custom tag which inspired this project. You can download his tag at http://www.illumineti.com/documents/xssblock.txt
	--->

	<!---Start of settings--->
	<cfset variables.instance.keepInnerText = false/> 								<!---Keep any text within a blocked tag--->
	<cfset variables.instance.invalidMarker = "[INVALID]"/>							<!---Strongly encouraged to replace stripped items with some type of marker, otherwise the attacker can rebuild a bad string from the stripping--->
	<cfset variables.instance.escapeChars = true/>									<!---So HtmlEditFormat and XMLFormat does not catch everything - we have a better method here--->
	<cfset variables.instance.checkReferer = true/> 								<!---For form variables only--->
	<cfset variables.instance.safeReferers = ""/> 									<!---Comma delimited list of sites that can send submit form variables to this site--->
	<cfset variables.instance.exceptionFields = ""/>							 	<!---Comma delimited list of fields not to scan--->
	<cfset variables.instance.allowJSAccessCookies = true/>							<!---Turn off Javascript access to cookies with the HttpOnly attribute - supported by only some browsers--->
	<cfset variables.instance.blockCRLF = true/>									<!---Block CRLF (carriage return line feed) hacks, this particular hack has limited abilities so this could be overkill--->

	<cfset variables.instance.sqlFilter = "select,insert,update,delete,create,drop,alter,declare,execute,xp_,sp_sqlexecute,table_cursor,cast\(,exec\(,eval\(,information_schema"/>
	<cfset variables.instance.tagFilter = "script,object,applet,embed,form,input,layer,ilayer,frame,iframe,frameset,param,meta,base,style,xss"/>
	<cfset variables.instance.wordFilter = "onLoad,onClick,onDblClick,onKeyDown,onKeyPress,onKeyUp,onMouseDown,onMouseOut,onMouseUp,onMouseOver,onBlur,onChange,onFocus,onSelect,javascript:,vbscript:,.cookie,.toString,:expr,:expression,.fromCharCode,String."/>
	<cfset variables.instance.thisServer = LCase(CGI.SERVER_NAME)/>
	<!---End of settings--->

	<cfset variables.internal.detected = false/>

	<cffunction name="init" output="false" access="public" returntype="Portcullis">
		<cfargument name="settings" required="false" type="Struct"/>
		<cfif StructKeyExists(arguments,"settings")>
			<cfset setSettings(arguments.settings)/>
		</cfif>
		<cfreturn this/>
	</cffunction>

	<cffunction name="setSettings" output="false" access="public" returntype="Any">
		<cfargument name="settings" required="true" type="Struct"/>
		<cfset var local = StructNew()/>
		<cfloop collection="#arguments.settings#" item="local.item">
			<cfset variables.instance[local.item] = arguments.settings[local.item]/>
		</cfloop>
	</cffunction>

	<cffunction name="getSettings" output="false" access="public" returntype="Any">
		<cfreturn variables.instance/>
	</cffunction>

	<cffunction name="scanInSequence" output="false" access="public" returntype="boolean">
		<cfargument name="url" required="true" type="Struct"/>
		<cfargument name="form" required="true" type="Struct"/>
		<cfargument name="cookie" required="true" type="Struct"/>

		<cfset var detected = false/>

		<cfset setSettings( { blockCRLF= false } )/>
		<cfset scan(arguments.form, "form")/>
		<cfset detected = detected OR variables.internal.detected/>

		<cfset setSettings( { blockCRLF= true } )/>
		<cfset scan(arguments.url, "url")/>
		<cfset detected = detected OR variables.internal.detected/>

		<cfset scan(arguments.cookie, "cookie", "", false)/>
		<cfset detected = detected OR variables.internal.detected/>

		<cfreturn detected />
	</cffunction>

	<cffunction name="scan" access="public" returntype="Void">
		<cfargument name="object" required="true" type="Struct"/>
		<cfargument name="objectname" required="true" type="String"/>
		<cfargument name="exceptionFields" required="false" type="String"/> 		<!---Comma delimited list of fields not to scan--->
		<cfargument name="scanAndFix" type="boolean" default="true"/>
		<cfset var item= ""/>
		<cfset var itemname= ""/>
		<cfset var exFF= variables.instance.exceptionFields/>
		<cfset var detected= 0/>
		<cfset var temp= StructNew()/>
		<cfset var newitem = ""/>
		<cfset var contents = ""/>
		<cfset var nameregex = "[^a-zA-Z0-9_]"/>
		<cfset var safe = StructNew()/>
		<cfset var tempname = ""/>

		<!---Clean up Ampersands and nonexistent names that may mess up variable naming later on--->
		<cfloop collection="#arguments.object#" item="item">
			<cfif isValidCFVariableName(item) EQ false>
				<!---Item name is invalid anyway in CF so we just dump it --->
				<cfset StructDelete(arguments.object,item,false)/>
			<cfelse>
				<cfset newitem = ReplaceNoCase(item,"&amp;","","ALL")/>
				<cfset newitem = ReplaceNoCase(newitem,"amp;","","ALL")/>
				<cfset contents = "#arguments.object[item]#"/>
				<cfset StructInsert(safe,"#newitem#",contents,true)/>
			</cfif>
		</cfloop>

		<cfif StructKeyExists(arguments,"exceptionFields") AND Len(arguments.exceptionFields) GT 0>
			<cfset exFF = exFF & "," & arguments.exceptionFields/>
		</cfif>

		<!---Filter Tags--->
		<cfloop collection="#safe#" item="item">
			<cfif NOT ListContainsNoCase(exFF,item,',')>
				<cfset temp = filterTags(safe[item])/>
				<cfset itemname = REReplaceNoCase(item,nameregex,"","All")/>
				<cfif temp.detected EQ true>
					<cfset detected = detected + 1/>
				<cfelse>
					<cfset temp = filterTags(URLDecode(safe[item]))/>
					<cfif temp.detected EQ true>
						<cfset detected = detected + 1/>
					</cfif>
				</cfif>
				<cfset safe[itemname] = temp.cleanText/>
			</cfif>
		</cfloop>

		<!---Filter Words--->
		<cfloop collection="#safe#" item="item">
			<cfif NOT ListContainsNoCase(exFF,item,',')>
				<cfset temp = filterWords(safe[item])/>
				<cfset itemname = REReplaceNoCase(item,nameregex,"","All")/>
				<cfif temp.detected EQ true>
					<cfset detected = detected + 1/>
				<cfelse>
					<cfset temp = filterWords(URLDecode(safe[item]))/>
					<cfif temp.detected EQ true>
						<cfset detected = detected + 1/>
					</cfif>
				</cfif>
				<cfset safe[itemname] = temp.cleanText/>
			</cfif>
		</cfloop>

		<!---Filter CRLF--->
		<cfif variables.instance.blockCRLF EQ true>
			<cfloop collection="#safe#" item="item">
				<cfif NOT ListContainsNoCase(exFF,item,',')>
					<cfset temp = filterCRLF(safe[item])/>
					<cfset itemname = REReplaceNoCase(item,nameregex,"","All")/>
					<!---<cfif temp.detected EQ true>
						<cfset detected = detected + 1/>
					<cfelse>
						<cfset temp = filterCRLF(URLDecode(safe[item]))/>
						<cfif temp.detected EQ true>
							<cfset detected = detected + 1/>
						</cfif>
					</cfif>  // We're not going to take note of CRLFs since it's very likely benign --->
					<cfset safe[itemname] = temp.cleanText/>
				</cfif>
			</cfloop>
		</cfif>

		<!---Filter SQL--->
		<cfloop collection="#safe#" item="item">
			<cfif NOT ListContainsNoCase(exFF,item,',')>
				<cfset temp = filterSQL(safe[item])/>
				<cfset itemname = REReplaceNoCase(item,nameregex,"","All")/>
				<cfif temp.detected EQ true>
					<cfset detected = detected + 1/>
				<cfelse>
					<cfset temp = filterSQL(URLDecode(safe[item]))/>
					<cfif temp.detected EQ true>
						<cfset detected = detected + 1/>
					</cfif>
				</cfif>
				<cfset safe[itemname] = temp.cleanText/>
			</cfif>
		</cfloop>

		<!---Escape Special Characters--->
		<cfif variables.instance.escapeChars EQ true>
			<cfloop collection="#safe#" item="item">
				<cfif NOT ListContainsNoCase(exFF,item,',')>
					<cfif isNumeric(safe[item]) EQ false>
						<cfset itemname = REReplaceNoCase(item,nameregex,"","All")/>
						<cfset temp = escapeChars(safe[item])/>
						<cfset safe[itemname] = temp/>
					</cfif>
				</cfif>
			</cfloop>
		</cfif>

		<cfif arguments.scanAndFix>
			<cfloop list="#StructKeyList(safe)#" index="itemname">
				<cfset tempname = safe[itemname]/>
				<cfset StructDelete(safe, itemname)/>
				<cfset safe[itemname] = tempname/>
			</cfloop>

			<cfset StructClear(arguments.object)/>

			<cfloop list="#StructKeyList(safe)#" index="itemname">
				<cfset arguments.object[itemname] = safe[itemname]/>
			</cfloop>
		</cfif>

		<cfif detected GT 0>
			<cfset variables.internal.detected = true/>
		<cfelse>
			<cfset variables.internal.detected = false/>
		</cfif>

	</cffunction>

	<cffunction name="filterTags" output="false" access="public" returntype="Any">
		<cfargument name="text" required="true" type="String"/>
		<cfset var result = StructNew()/>
		<cfset var tag = ""/>
		<cfset var tcount = 0/>
		<cfset var lcount = 0/>

		<!---trim white space and deal with "smart quotes" from MS Word, etc. This code came from Shawn Gorrell's popular cf_xssblock tag - http://www.illumineti.com/documents/xssblock.txt --->
		<cfset result.originalText = Trim(ReplaceList(arguments.text,chr(8216) & "," & chr(8217) & "," & chr(8220) & "," & chr(8221) & "," & chr(8212) & "," & chr(8213) & "," & chr(8230),"',',"","",--,--,..."))/>

		<!--- strike all comments --->
		<cfset result.originaltext = REReplace(result.originaltext, "/\*(.*?)\*/", "", "ALL")/>
		<cfset result.originaltext = REReplace(result.originaltext, "<!\-\-(.*?)\-\->", "", "ALL")/>

		<cfset result.detected = true/>
		<cfset result.cleanText = result.originalText/>
		<cfloop index="tag" list="#variables.instance.tagFilter#">
			<cfif REFindNoCase(("<#tag#\b.*?>|<#tag#\b.*?/>"),result.cleanText) EQ 0>
				<cfset tcount = tcount + 1/>
			</cfif>
			<cfset lcount = lcount + 1/>
		</cfloop>

		<cfif tcount EQ lcount>
			<cfset result.detected = false/>
		</cfif>

		<cfreturn result/>
	</cffunction>

	<cffunction name="filterWords" output="false" access="public" returntype="Any">
		<cfargument name="text" required="true" type="String"/>
		<cfset var result = StructNew()/>
		<cfset result.detected = true/>
		<cfset result.originalText = Trim(arguments.text)/>	<!---trim white space and deal with "smart quotes" from MS Word, etc.--->
		<cfset result.originalText = REReplace(arguments.text,"(‘|’)", "'", "ALL") />	<!---trim white space and deal with "smart quotes" from MS Word, etc.--->
		<cfset result.originalText = REReplace(arguments.text,"(“|”)", '"', "ALL") />	<!---trim white space and deal with "smart quotes" from MS Word, etc.--->

		<cfset result.filter = variables.instance.wordFilter />
		<cfset result.text = arguments.text />

		<cfset result.filtArr = ListToArray( result.filter )/>
		<cfset result.detected = ArrayContains( result.filtArr, result.text ) />

		<cfset result.cleanText = result.originalText/>

		<cfreturn result/>
	</cffunction>

	<cffunction name="filterSQL" output="false" access="public" returntype="Any">
		<cfargument name="text" required="true" type="String"/>
		<cfset var result = StructNew()/>
		<cfset var sqlcmdword = ""/>
		<cfset var tcount = 0/>
		<cfset var lcount = 0/>
		<cfset result.detected = true/>
		<cfset result.originalText = arguments.text/>
		<cfset result.cleanText = arguments.text/>

		<cfloop index="sqlcmdword" list="#variables.instance.sqlFilter#">
			<cfif REFindNoCase("[[:punct:]]",sqlcmdword) EQ 0>
				<cfif REFindNoCase( '\b' & sqlcmdword & '\b',arguments.text) EQ 0>
					<cfset tcount = tcount + 1/>
				<cfelse>
					<!---Simple sql command word - need to check for the context of use--->
					<cfif badSQLContext(sqlcmdword,arguments.text) NEQ true>
						<cfset tcount = tcount + 1/>
					</cfif>
				</cfif>
			<cfelse>
				<!---Advance sql command word - no need for context check--->
				<cfif REFindNoCase( '\b' & sqlcmdword & '\b',arguments.text) EQ 0>
					<cfset tcount = tcount + 1/>
				</cfif>
			</cfif>
			<cfset lcount = lcount + 1/>
		</cfloop>

		<cfif tcount EQ lcount>
			<cfset result.detected = false/>
		</cfif>

		<cfreturn result/>
	</cffunction>

	<!--- Some SQL command words are commonly used in everyday language like update and alter - this method determines if the context appears malign--->
	<cffunction name="badSQLContext" output="false" access="public" returntype="Any">
		<cfargument name="sqlcmdword" required="true" type="String"/>
		<cfargument name="text" required="true" type="String"/>

		<cfset local.tcount = 0/>
		<cfset local.lcount = 0/>
		<cfset local.afterwords = ""/>
		<cfset local.cmdwords1 = "create,drop,alter"/>
		<cfset local.dbobjects = "database,default,function,index,procedure,rule,schema,statistics,table,trigger,view"/>
		<cfset local.cmdwords2 = "select,insert,update,delete"/>
		<cfset local.dbverbs = "from,@,into,where,group,having,order,union"/>
		<cfset local.result = true/>

		<cfif REFindNoCase((ListChangeDelims(local.cmdwords1,"|")),arguments.sqlcmdword) GT 0>
			<cfset local.afterwords = local.dbobjects/>
		<cfelseif REFindNoCase((ListChangeDelims(local.cmdwords2,"|")),arguments.sqlcmdword) GT 0>
			<cfset local.afterwords = local.dbverbs/>
		<cfelse>
			<cfset local.afterwords = local.dbobjects & "," & local.dbverbs/>
		</cfif>

		<cfloop index="local.word" list="#local.afterwords#">
			<cfset local.temp = "\b#sqlcmdword#\b.*?\b#local.word#\b"/>
			<cfif REFindNoCase(local.temp,arguments.text) EQ 0>
				<cfset local.tcount = local.tcount + 1/>
			</cfif>
			<cfset local.lcount = local.lcount + 1/>
		</cfloop>

		<cfif local.tcount EQ local.lcount>
			<cfset local.result = false/>
		</cfif>

		<cfreturn local.result/>
	</cffunction>

	<cffunction name="filterCRLF" output="false" access="public" returntype="Any">
		<cfargument name="text" required="true" type="String"/>
		<cfset var result = StructNew()/>
		<cfset result.detected = true/>
		<cfset result.originalText = arguments.text/>

		<cfif REFindNoCase(chr(13),arguments.text) EQ 0 AND REFindNoCase(chr(10),arguments.text) EQ 0>
			<cfset result.detected = false/>
			<cfset result.cleanText = result.originalText/>
		<cfelse>
			<cfset result.cleanText = REReplaceNoCase(arguments.text,chr(13),"","ALL")/>
			<cfset result.cleanText = REReplaceNoCase(result.cleanText,chr(10)," ","ALL")/>
		</cfif>
		<cfreturn result/>
	</cffunction>

	<!---HTMLEditFormat and XMLFormat simply don't do enough, so we do far more here--->
	<cffunction name="escapeChars" output="false" access="public" returntype="Any">
		<cfargument name="text" required="true" type="String"/>
		<cfset var result = arguments.text/>

		<cfset result = ReplaceNoCase(result,";","[semicolon]","ALL")/>
		<cfset result = ReplaceNoCase(result,"##","&##35;","ALL")/>
		<cfset result = ReplaceNoCase(result,"(","&##40;","ALL")/>
		<cfset result = ReplaceNoCase(result,")","&##41;","ALL")/>
		<cfset result = ReplaceNoCase(result,"<","&lt;","ALL")/>
		<cfset result = ReplaceNoCase(result,">","&GT;","ALL")/>
		<cfset result = ReplaceNoCase(result,"'","&##39;","ALL")/>
		<cfset result = ReplaceNoCase(result,"""","&quot;","ALL")/>
		<cfset result = ReplaceNoCase(result,"[semicolon]","&##59;","ALL")/>

		<cfreturn result/>
	</cffunction>

	<cffunction name="isSafeReferer" output="false" access="public" returntype="Any">
		<cfset var thisserver = LCase(CGI.SERVER_NAME)/>
		<cfset var thisreferer = "none"/>
		<cfset var isSafe = false/> <!---We assume false until it's verified--->

		<cfif StructKeyExists(cgi,"HTTP_REFERER") AND Len(cgi.HTTP_REFERER)>
			<cfset thisreferer = Replace(LCase(CGI.HTTP_REFERER),'http://','','all')/>
			<cfset thisreferer = Replace(thisreferer,'https://','','all')/>
			<cfset thisreferer = ListGetAt(thisreferer,1,'/')/>
		<cfelse>
			<cfset thisreferer = "none"/>
		</cfif>

		<cfif thisreferer EQ "none" OR thisreferer EQ thisserver>
			<cfset isSafe = true/>
		<cfelse>
			<cfif ListContainsNoCase(variables.instance.safeReferers,thisreferer,',')>
				<cfset isSafe = true/>
			</cfif>
		</cfif>

		<cfreturn isSafe/>
	</cffunction>

	<!---Sometimes submitted variable names which are valid in other languages are not usable in CF due to its Variable naming rules--->
	<cffunction name="isValidCFVariableName" output="false" access="public" returntype="Any">
		<cfargument name="text" required="true" type="String"/>
		<cfset var local = StructNew()/>
		<cfset local.result = true/>

		<cfif Len(arguments.text) EQ 0>
			<cfset local.result = false/>
		<cfelseif FindNoCase(".",arguments.text) GT 0>
			<cfset local.result = false/>
		<cfelseif FindNoCase(" ",arguments.text) GT 0>
			<cfset local.result = false/>
		<cfelseif ReFindNoCase("^[A-Za-z][A-Za-z0-9_]*",arguments.text) EQ 0>
			<cfset local.result = false/>
		</cfif>

		<cfreturn local.result/>
	</cffunction>

	<cffunction name="isDetected" output="false" access="public" returntype="Any">
		<cfreturn variables.internal.detected/>
	</cffunction>

</cfcomponent>
