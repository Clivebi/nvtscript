if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.70731" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2011-2720" );
	script_version( "$Revision: 11762 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2012-02-12 07:27:19 -0500 (Sun, 12 Feb 2012)" );
	script_name( "FreeBSD Ports: glpi" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following package is affected: glpi

CVE-2011-2720
The autocompletion functionality in GLPI before 0.80.2 does not
blacklist certain username and password fields, which allows remote
attackers to obtain sensitive information via a crafted POST request." );
	script_tag( name: "solution", value: "Update your system with the appropriate patches or
  software upgrades." );
	script_xref( name: "URL", value: "http://www.glpi-project.org/spip.php?page=annonce&id_breve=237&lang=en" );
	script_xref( name: "URL", value: "https://forge.indepnet.net/issues/3017" );
	script_xref( name: "URL", value: "http://www.vuxml.org/freebsd/7c769c89-53c2-11e1-8e52-00163e22ef61.html" );
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
bver = portver( pkg: "glpi" );
if(!isnull( bver ) && revcomp( a: bver, b: "0.80.2" ) < 0){
	txt += "Package glpi version " + bver + " is installed which is known to be vulnerable.\n";
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

