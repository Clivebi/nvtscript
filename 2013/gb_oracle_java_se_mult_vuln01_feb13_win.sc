if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803307" );
	script_version( "$Revision: 12047 $" );
	script_cve_id( "CVE-2013-0431", "CVE-2013-1489", "CVE-2013-0351", "CVE-2013-0409", "CVE-2013-0419", "CVE-2013-0423", "CVE-2013-0424", "CVE-2012-3342", "CVE-2012-3213", "CVE-2012-1541", "CVE-2013-1475", "CVE-2013-0425", "CVE-2013-0426", "CVE-2013-0446", "CVE-2013-0448", "CVE-2013-0449", "CVE-2013-0450", "CVE-2013-1473", "CVE-2013-1476", "CVE-2013-1478", "CVE-2013-1479", "CVE-2013-1480", "CVE-2013-0435", "CVE-2013-0434", "CVE-2013-0433", "CVE-2013-0432", "CVE-2013-0430", "CVE-2013-0429", "CVE-2013-0428", "CVE-2013-0437", "CVE-2013-0438", "CVE-2013-1481", "CVE-2013-0445", "CVE-2013-0444", "CVE-2013-0443", "CVE-2013-0442", "CVE-2013-0441", "CVE-2013-0440", "CVE-2013-0427" );
	script_bugtraq_id( 57707, 57702, 57708, 57712, 57715, 57719, 57723, 57724, 57726, 57728, 57681, 57686, 57687, 57689, 57691, 57692, 57694, 57696, 57697, 57699, 57700, 57703, 57706, 57709, 57711, 57713, 57717, 57718, 57701, 57704, 57710, 57714, 57716, 57720, 57722, 57727, 57731, 57729, 57730 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-24 09:38:41 +0200 (Wed, 24 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2013-02-06 18:29:04 +0530 (Wed, 06 Feb 2013)" );
	script_name( "Oracle Java SE Multiple Vulnerabilities -01 Feb 13 (Windows)" );
	script_xref( name: "URL", value: "http://securitytracker.com/id/1028071" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/topics/security/javacpufeb2013-1841061.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_java_prdts_detect_portable_win.sc" );
	script_mandatory_keys( "Sun/Java/JRE/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation allows remote attackers to affect confidentiality,
  integrity, and availability via unknown vectors. Attackers can even execute
  arbitrary code on the target system." );
	script_tag( name: "affected", value: "Oracle Java SE Version 7 Update 11 and earlier, 6 Update 38 and earlier,
  5 Update 38 and earlier and 1.4.2_40 and earlier." );
	script_tag( name: "insight", value: "Multiple flaws due to unspecified errors in the following components:

  - Deployment

  - Scripting

  - COBRA

  - Sound

  - Beans

  - 2D

  - Networking

  - Libraries

  - Installation process of client

  - Abstract Window Toolkit (AWT)

  - Remote Method Invocation (RMI)

  - Java Management Extensions (JMX)

  - Java API for XML Web Services(JAX_WS)

  - Java Secure Socket Extension (JSSE)" );
	script_tag( name: "solution", value: "Apply the patch from the referenced advisory." );
	script_tag( name: "summary", value: "This host is installed with Oracle Java SE and is prone to
  multiple vulnerabilities." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
jreVer = get_kb_item( "Sun/Java/JRE/Win/Ver" );
if(jreVer){
	if(version_is_less_equal( version: jreVer, test_version: "1.4.2.40" ) || version_in_range( version: jreVer, test_version: "1.7", test_version2: "1.7.0.11" ) || version_in_range( version: jreVer, test_version: "1.6", test_version2: "1.6.0.38" ) || version_in_range( version: jreVer, test_version: "1.5", test_version2: "1.5.0.38" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}

