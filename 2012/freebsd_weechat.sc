if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.72600" );
	script_version( "$Revision: 12634 $" );
	script_cve_id( "CVE-2012-5534" );
	script_tag( name: "last_modification", value: "$Date: 2018-12-04 08:26:26 +0100 (Tue, 04 Dec 2018) $" );
	script_tag( name: "creation_date", value: "2012-11-26 12:47:32 -0500 (Mon, 26 Nov 2012)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "FreeBSD Ports: weechat" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following packages are affected:

  weechat, weechat-devel" );
	script_tag( name: "solution", value: "Update your system with the appropriate patches or
  software upgrades." );
	script_xref( name: "URL", value: "http://weechat.org/security/" );
	script_xref( name: "URL", value: "https://savannah.nongnu.org/bugs/?37764" );
	script_xref( name: "URL", value: "http://www.vuxml.org/freebsd/81826d12-317a-11e2-9186-406186f3d89d.html" );
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
bver = portver( pkg: "weechat" );
if(!isnull( bver ) && revcomp( a: bver, b: "0.3.0" ) >= 0 && revcomp( a: bver, b: "0.3.9.2" ) < 0){
	txt += "Package weechat version " + bver + " is installed which is known to be vulnerable.\\n";
	vuln = TRUE;
}
bver = portver( pkg: "weechat-devel" );
if(!isnull( bver ) && revcomp( a: bver, b: "20121118" ) < 0){
	txt += "Package weechat-devel version " + bver + " is installed which is known to be vulnerable.\\n";
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

