if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71848" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2012-3422", "CVE-2012-3423" );
	script_version( "$Revision: 11762 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2012-08-30 11:34:18 -0400 (Thu, 30 Aug 2012)" );
	script_name( "FreeBSD Ports: icedtea-web" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following package is affected: icedtea-web

CVE-2012-3422
The getFirstInTableInstance function in the IcedTea-Web plugin before
1.2.1 returns an uninitialized pointer when the instance_to_id_map
hash is empty, which allows remote attackers to cause a denial of
service (crash) and possibly execute arbitrary code via a crafted web
page, which causes an uninitialized memory location to be read.
CVE-2012-3423
The IcedTea-Web plugin before 1.2.1 does not properly handle NPVariant
NPStrings without NUL terminators, which allows remote attackers to
cause a denial of service (crash), obtain sensitive information from
memory, or execute arbitrary code via a crafted Java applet." );
	script_tag( name: "solution", value: "Update your system with the appropriate patches or
  software upgrades." );
	script_xref( name: "URL", value: "http://mail.openjdk.java.net/pipermail/distro-pkg-dev/2012-July/019580.html" );
	script_xref( name: "URL", value: "http://www.vuxml.org/freebsd/55b498e2-e56c-11e1-bbd5-001c25e46b1d.html" );
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
bver = portver( pkg: "icedtea-web" );
if(!isnull( bver ) && revcomp( a: bver, b: "1.2.1" ) < 0){
	txt += "Package icedtea-web version " + bver + " is installed which is known to be vulnerable.\\n";
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

