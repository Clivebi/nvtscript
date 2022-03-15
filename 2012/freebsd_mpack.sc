if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.70745" );
	script_cve_id( "CVE-2011-4919" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_version( "2021-08-27T12:57:20+0000" );
	script_tag( name: "last_modification", value: "2021-08-27 12:57:20 +0000 (Fri, 27 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-11-21 15:45:00 +0000 (Thu, 21 Nov 2019)" );
	script_tag( name: "creation_date", value: "2012-02-12 07:27:20 -0500 (Sun, 12 Feb 2012)" );
	script_name( "FreeBSD Ports: mpack" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 E-Soft Inc." );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following package is affected: mpack" );
	script_tag( name: "solution", value: "Update your system with the appropriate patches or
  software upgrades." );
	script_xref( name: "URL", value: "http://openwall.com/lists/oss-security/2011/12/31/1" );
	script_xref( name: "URL", value: "http://www.vuxml.org/freebsd/e465159c-4817-11e1-89b4-001ec9578670.html" );
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
bver = portver( pkg: "mpack" );
if(!isnull( bver ) && revcomp( a: bver, b: "1.6_3" ) < 0){
	txt += "Package mpack version " + bver + " is installed which is known to be vulnerable.\n";
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

