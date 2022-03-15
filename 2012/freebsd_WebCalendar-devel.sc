if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71385" );
	script_cve_id( "CVE-2012-1495", "CVE-2012-1496" );
	script_version( "2021-08-27T12:28:31+0000" );
	script_tag( name: "last_modification", value: "2021-08-27 12:28:31 +0000 (Fri, 27 Aug 2021)" );
	script_tag( name: "creation_date", value: "2012-05-31 11:53:51 -0400 (Thu, 31 May 2012)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-01-29 20:36:00 +0000 (Wed, 29 Jan 2020)" );
	script_name( "FreeBSD Ports: WebCalendar-devel" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 E-Soft Inc." );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following package is affected: WebCalendar-devel" );
	script_tag( name: "solution", value: "Update your system with the appropriate patches or
  software upgrades." );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/112332/WebCalendar-1.2.4-Remote-Code-Execution.html" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/112323/WebCalendar-1.2.4-Pre-Auth-Remote-Code-Injection.html" );
	script_xref( name: "URL", value: "http://archives.neohapsis.com/archives/bugtraq/2012-04/0182.html" );
	script_xref( name: "URL", value: "http://www.vuxml.org/freebsd/18dffa02-946a-11e1-be9d-000c29cc39d3.html" );
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
bver = portver( pkg: "WebCalendar-devel" );
if(!isnull( bver ) && revcomp( a: bver, b: "1.2.4" ) <= 0){
	txt += "Package WebCalendar-devel version " + bver + " is installed which is known to be vulnerable.\\n";
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

