if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71370" );
	script_cve_id( "CVE-2011-3202" );
	script_version( "2021-08-27T12:28:31+0000" );
	script_tag( name: "last_modification", value: "2021-08-27 12:28:31 +0000 (Fri, 27 Aug 2021)" );
	script_tag( name: "creation_date", value: "2012-05-31 11:53:51 -0400 (Thu, 31 May 2012)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-01-16 15:19:00 +0000 (Thu, 16 Jan 2020)" );
	script_name( "FreeBSD Ports: libxml2" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 E-Soft Inc." );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following package is affected: libxml2" );
	script_tag( name: "solution", value: "Update your system with the appropriate patches or
  software upgrades." );
	script_xref( name: "URL", value: "http://googlechromereleases.blogspot.com/2012/05/stable-channel-update.html" );
	script_xref( name: "URL", value: "https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2011-3102" );
	script_xref( name: "URL", value: "http://www.vuxml.org/freebsd/b8ae4659-a0da-11e1-a294-bcaec565249c.html" );
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
bver = portver( pkg: "libxml2" );
if(!isnull( bver ) && revcomp( a: bver, b: "2.7.8_3" ) < 0){
	txt += "Package libxml2 version " + bver + " is installed which is known to be vulnerable.\\n";
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

