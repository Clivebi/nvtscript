if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71157" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2011-3047" );
	script_version( "2020-04-21T07:31:29+0000" );
	script_tag( name: "last_modification", value: "2020-04-21 07:31:29 +0000 (Tue, 21 Apr 2020)" );
	script_tag( name: "creation_date", value: "2012-03-12 11:35:07 -0400 (Mon, 12 Mar 2012)" );
	script_name( "FreeBSD Ports: chromium" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following package is affected: chromium

CVE-2011-3047
The GPU process in Google Chrome before 17.0.963.79 allows remote
attackers to execute arbitrary code or cause a denial of service
(memory corruption) by leveraging an error in the plug-in loading
mechanism." );
	script_tag( name: "solution", value: "Update your system with the appropriate patches or
  software upgrades." );
	script_xref( name: "URL", value: "http://googlechromereleases.blogspot.com/search/label/Stable%20updates" );
	script_xref( name: "URL", value: "http://www.vuxml.org/freebsd/ab1f515d-6b69-11e1-8288-00262d5ed8ee.html" );
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
bver = portver( pkg: "chromium" );
if(!isnull( bver ) && revcomp( a: bver, b: "17.0.963.79" ) < 0){
	txt += "Package chromium version " + bver + " is installed which is known to be vulnerable.\\n";
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

