if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.70621" );
	script_tag( name: "creation_date", value: "2012-02-13 01:48:16 +0100 (Mon, 13 Feb 2012)" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2011-3342" );
	script_version( "$Revision: 11762 $" );
	script_name( "FreeBSD Ports: openttd" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following package is affected: openttd

CVE-2011-3342
Multiple buffer overflows in OpenTTD before 1.1.3 allow remote
attackers to cause a denial of service (daemon crash) or possibly
execute arbitrary code via vectors related to (1) NAME, (2) PLYR, (3)
CHTS, or (4) AIPL (aka AI config) chunk loading from a savegame." );
	script_tag( name: "solution", value: "Update your system with the appropriate patches or
  software upgrades." );
	script_xref( name: "URL", value: "http://security.openttd.org/en/CVE-2011-3342" );
	script_xref( name: "URL", value: "http://www.vuxml.org/freebsd/78c25ed7-f3f9-11e0-8b5c-b482fe3f522d.html" );
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
bver = portver( pkg: "openttd" );
if(!isnull( bver ) && revcomp( a: bver, b: "0.1.0" ) >= 0 && revcomp( a: bver, b: "1.1.3" ) < 0){
	txt += "Package openttd version " + bver + " is installed which is known to be vulnerable.\n";
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

