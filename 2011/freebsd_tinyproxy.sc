if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.69602" );
	script_version( "$Revision: 11762 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2011-05-12 19:21:50 +0200 (Thu, 12 May 2011)" );
	script_tag( name: "cvss_base", value: "2.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:N/I:P/A:N" );
	script_cve_id( "CVE-2011-1499" );
	script_name( "FreeBSD Ports: tinyproxy" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following package is affected: tinyproxy

CVE-2011-1499
acl.c in Tinyproxy before 1.8.3, when an Allow configuration setting
specifies a CIDR block, permits TCP connections from all IP addresses,
which makes it easier for remote attackers to hide the origin of web
traffic by leveraging the open HTTP proxy server." );
	script_tag( name: "solution", value: "Update your system with the appropriate patches or
  software upgrades." );
	script_xref( name: "URL", value: "https://banu.com/bugzilla/show_bug.cgi?id=90" );
	script_xref( name: "URL", value: "http://www.vuxml.org/freebsd/b9281fb9-61b2-11e0-b1ce-0019d1a7ece2.html" );
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
bver = portver( pkg: "tinyproxy" );
if(!isnull( bver ) && revcomp( a: bver, b: "1.8.2_2,1" ) < 0){
	txt += "Package tinyproxy version " + bver + " is installed which is known to be vulnerable.\n";
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

