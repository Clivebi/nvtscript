if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.68832" );
	script_version( "$Revision: 11762 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2011-01-24 17:55:59 +0100 (Mon, 24 Jan 2011)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_cve_id( "CVE-2006-7243" );
	script_name( "FreeBSD Ports: php5" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following packages are affected:

  php5
   php52

CVE-2006-7243
PHP before 5.3.4 accepts the \\0 character in a pathname, which might
allow context-dependent attackers to bypass intended access
restrictions by placing a safe file extension after this character, as
demonstrated by .php\\0.jpg at the end of the argument to the
file_exists function." );
	script_tag( name: "solution", value: "Update your system with the appropriate patches or
  software upgrades." );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/archive/1/445788/100/0/threaded" );
	script_xref( name: "URL", value: "http://artofhacking.com/files/phrack/phrack55/P55-07.TXT" );
	script_xref( name: "URL", value: "http://www.vuxml.org/freebsd/3761df02-0f9c-11e0-becc-0022156e8794.html" );
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
bver = portver( pkg: "php5" );
if(!isnull( bver ) && revcomp( a: bver, b: "5.3.4" ) < 0){
	txt += "Package php5 version " + bver + " is installed which is known to be vulnerable.\n";
	vuln = TRUE;
}
bver = portver( pkg: "php52" );
if(!isnull( bver ) && revcomp( a: bver, b: "0" ) >= 0){
	txt += "Package php52 version " + bver + " is installed which is known to be vulnerable.\n";
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

