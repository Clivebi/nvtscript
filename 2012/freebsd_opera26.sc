if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.72597" );
	script_version( "$Revision: 11762 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2012-11-26 12:47:32 -0500 (Mon, 26 Nov 2012)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "FreeBSD Ports: opera, opera-devel, linux-opera, linux-opera-devel" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following packages are affected:

  opera

  opera-devel

  linux-opera

  linux-opera-devel" );
	script_tag( name: "solution", value: "Update your system with the appropriate patches or
  software upgrades." );
	script_xref( name: "URL", value: "http://www.opera.com/support/kb/view/1036/" );
	script_xref( name: "URL", value: "http://www.vuxml.org/freebsd/0925716f-34e2-11e2-aa75-003067c2616f.html" );
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
bver = portver( pkg: "opera" );
if(!isnull( bver ) && revcomp( a: bver, b: "12.11" ) < 0){
	txt += "Package opera version " + bver + " is installed which is known to be vulnerable.\\n";
	vuln = TRUE;
}
bver = portver( pkg: "opera-devel" );
if(!isnull( bver ) && revcomp( a: bver, b: "12.11" ) < 0){
	txt += "Package opera-devel version " + bver + " is installed which is known to be vulnerable.\\n";
	vuln = TRUE;
}
bver = portver( pkg: "linux-opera" );
if(!isnull( bver ) && revcomp( a: bver, b: "12.11" ) < 0){
	txt += "Package linux-opera version " + bver + " is installed which is known to be vulnerable.\\n";
	vuln = TRUE;
}
bver = portver( pkg: "linux-opera-devel" );
if(!isnull( bver ) && revcomp( a: bver, b: "12.11" ) < 0){
	txt += "Package linux-opera-devel version " + bver + " is installed which is known to be vulnerable.\\n";
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

