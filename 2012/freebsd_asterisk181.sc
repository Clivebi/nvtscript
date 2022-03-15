if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.70618" );
	script_tag( name: "creation_date", value: "2012-02-13 01:48:16 +0100 (Mon, 13 Feb 2012)" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $" );
	script_cve_id( "CVE-2011-4063" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:C" );
	script_version( "$Revision: 11762 $" );
	script_name( "FreeBSD Ports: asterisk18" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following packages are affected:

  asterisk18
   asterisk

CVE-2011-4063
chan_sip.c in the SIP channel driver in Asterisk Open Source 1.8.x
before 1.8.7.1 and 10.x before 10.0.0-rc1 does not properly initialize
variables during request parsing, which allows remote authenticated
users to cause a denial of service (daemon crash) via a malformed
request." );
	script_tag( name: "solution", value: "Update your system with the appropriate patches or
  software upgrades." );
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
bver = portver( pkg: "asterisk18" );
if(!isnull( bver ) && revcomp( a: bver, b: "1.8" ) > 0 && revcomp( a: bver, b: "1.8.7.1" ) < 0){
	txt += "Package asterisk18 version " + bver + " is installed which is known to be vulnerable.\n";
	vuln = TRUE;
}
bver = portver( pkg: "asterisk" );
if(!isnull( bver ) && revcomp( a: bver, b: "10.0.0" ) > 0 && revcomp( a: bver, b: "10.0.0.r1" ) < 0){
	txt += "Package asterisk version " + bver + " is installed which is known to be vulnerable.\n";
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

