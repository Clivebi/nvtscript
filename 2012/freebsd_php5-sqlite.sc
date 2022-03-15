if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.72400" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_cve_id( "CVE-2012-3365" );
	script_version( "$Revision: 11762 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2012-09-19 11:49:14 -0400 (Wed, 19 Sep 2012)" );
	script_name( "FreeBSD Ports: php5-sqlite" );
	script_xref( name: "URL", value: "http://www.vuxml.org/freebsd/ec255bd8-02c6-11e2-92d1-000d601460a4.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following packages are affected:

  php5-sqlite
   php52-sqlite
   php53-sqlite

CVE-2012-3365
The SQLite functionality in PHP before 5.3.15 allows remote attackers
to bypass the open_basedir protection mechanism via unspecified
vectors." );
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
bver = portver( pkg: "php5-sqlite" );
if(!isnull( bver ) && revcomp( a: bver, b: "5.2" ) >= 0 && revcomp( a: bver, b: "5.2.17_11" ) < 0){
	txt += "Package php5-sqlite version " + bver + " is installed which is known to be vulnerable.\\n";
	vuln = TRUE;
}
if(!isnull( bver ) && revcomp( a: bver, b: "5.3" ) >= 0 && revcomp( a: bver, b: "5.3.15" ) < 0){
	txt += "Package php5-sqlite version " + bver + " is installed which is known to be vulnerable.\\n";
	vuln = TRUE;
}
bver = portver( pkg: "php52-sqlite" );
if(!isnull( bver ) && revcomp( a: bver, b: "5.2.17_11" ) < 0){
	txt += "Package php52-sqlite version " + bver + " is installed which is known to be vulnerable.\\n";
	vuln = TRUE;
}
bver = portver( pkg: "php53-sqlite" );
if(!isnull( bver ) && revcomp( a: bver, b: "5.3.15" ) < 0){
	txt += "Package php53-sqlite version " + bver + " is installed which is known to be vulnerable.\\n";
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

