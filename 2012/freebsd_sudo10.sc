if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.70739" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2012-0809" );
	script_version( "$Revision: 11762 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2012-02-12 07:27:19 -0500 (Sun, 12 Feb 2012)" );
	script_name( "FreeBSD Ports: sudo" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following package is affected: sudo

CVE-2012-0809
Format string vulnerability in the sudo_debug function in Sudo 1.8.0
through 1.8.3p1 allows local users to execute arbitrary code via
format string sequences in the program name for sudo." );
	script_tag( name: "solution", value: "Update your system with the appropriate patches or
  software upgrades." );
	script_xref( name: "URL", value: "http://www.gratisoft.us/sudo/alerts/sudo_debug.html" );
	script_xref( name: "URL", value: "http://www.vuxml.org/freebsd/7c920bb7-4b5f-11e1-9f47-00e0815b8da8.html" );
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
bver = portver( pkg: "sudo" );
if(!isnull( bver ) && revcomp( a: bver, b: "1.8.0" ) >= 0 && revcomp( a: bver, b: "1.8.3_2" ) < 0){
	txt += "Package sudo version " + bver + " is installed which is known to be vulnerable.\n";
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

