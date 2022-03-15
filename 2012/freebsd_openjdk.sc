if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71831" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2012-4681" );
	script_version( "$Revision: 11762 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2012-08-30 11:34:17 -0400 (Thu, 30 Aug 2012)" );
	script_name( "FreeBSD Ports: openjdk" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following packages are affected:

  openjdk
   linux-sun-jdk
   linux-sun-jre

CVE-2012-4681
Oracle Java 7 Update 6, and possibly other versions, allows remote
attackers to execute arbitrary code via a crafted applet, as exploited
in the wild in August 2012 using Gondzz.class and Gondvv.class." );
	script_tag( name: "solution", value: "Update your system with the appropriate patches or
  software upgrades." );
	script_xref( name: "URL", value: "http://www.deependresearch.org/2012/08/java-7-vulnerability-analysis.html" );
	script_xref( name: "URL", value: "http://mail.openjdk.java.net/pipermail/distro-pkg-dev/2012-August/020065.html" );
	script_xref( name: "URL", value: "http://www.vuxml.org/freebsd/16846d1e-f1de-11e1-8bd8-0022156e8794.html" );
	script_tag( name: "summary", value: "The remote host is missing an update to the system
  as announced in the referenced advisory." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-bsd.inc.sc");
vuln = FALSE;
txt = "";
bver = portver( pkg: "openjdk" );
if(!isnull( bver ) && revcomp( a: bver, b: "7.0" ) >= 0 && revcomp( a: bver, b: "7.6.24_1" ) < 0){
	txt += "Package openjdk version " + bver + " is installed which is known to be vulnerable.\\n";
	vuln = TRUE;
}
bver = portver( pkg: "linux-sun-jdk" );
if(!isnull( bver ) && revcomp( a: bver, b: "7.0" ) >= 0){
	txt += "Package linux-sun-jdk version " + bver + " is installed which is known to be vulnerable.\\n";
	vuln = TRUE;
}
bver = portver( pkg: "linux-sun-jre" );
if(!isnull( bver ) && revcomp( a: bver, b: "7.0" ) >= 0){
	txt += "Package linux-sun-jre version " + bver + " is installed which is known to be vulnerable.\\n";
	vuln = TRUE;
}
if( vuln ){
	security_message( data: txt );
}
else {
	if(__pkg_match){
		exit( 99 );
	}
}

