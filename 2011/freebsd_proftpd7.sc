if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.68702" );
	script_version( "$Revision: 14170 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-14 10:24:12 +0100 (Thu, 14 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-01-24 17:55:59 +0100 (Mon, 24 Jan 2011)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2010-4221" );
	script_bugtraq_id( 44562 );
	script_name( "FreeBSD Ports: proftpd" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following package is affected: proftpd

CVE-2010-4221
Multiple stack-based buffer overflows in the pr_netio_telnet_gets
function in netio.c in ProFTPD before 1.3.3c allow remote attackers to
execute arbitrary code via vectors involving a TELNET IAC escape
character to a (1) FTP or (2) FTPS server." );
	script_tag( name: "solution", value: "Update your system with the appropriate patches or
  software upgrades." );
	script_xref( name: "URL", value: "http://www.zerodayinitiative.com/advisories/ZDI-10-229/" );
	script_xref( name: "URL", value: "http://www.vuxml.org/freebsd/533d20e7-f71f-11df-9ae1-000bcdf0a03b.html" );
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
bver = portver( pkg: "proftpd" );
if(!isnull( bver ) && revcomp( a: bver, b: "1.3.3c" ) < 0){
	txt += "Package proftpd version " + bver + " is installed which is known to be vulnerable.\n";
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

