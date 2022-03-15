if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.70727" );
	script_cve_id( "CVE-2012-0846" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_version( "$Revision: 11762 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2012-02-12 07:27:19 -0500 (Sun, 12 Feb 2012)" );
	script_name( "FreeBSD Ports: WebCalendar" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following packages are affected:

  WebCalendar
   WebCalendar-devel" );
	script_tag( name: "solution", value: "Update your system with the appropriate patches or
  software upgrades." );
	script_xref( name: "URL", value: "http://sourceforge.net/tracker/?func=detail&amp;aid=3472745&group_id=3870&atid=103870" );
	script_xref( name: "URL", value: "http://www.vuxml.org/freebsd/2b20fd5f-552e-11e1-9fb7-003067b2972c.html" );
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
bver = portver( pkg: "WebCalendar" );
if(!isnull( bver ) && revcomp( a: bver, b: "1.2.4" ) < 0){
	txt += "Package WebCalendar version " + bver + " is installed which is known to be vulnerable.\n";
	vuln = TRUE;
}
bver = portver( pkg: "WebCalendar-devel" );
if(!isnull( bver ) && revcomp( a: bver, b: "1.2.4" ) < 0){
	txt += "Package WebCalendar-devel version " + bver + " is installed which is known to be vulnerable.\n";
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

