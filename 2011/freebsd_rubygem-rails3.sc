if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.70258" );
	script_version( "$Revision: 11762 $" );
	script_cve_id( "CVE-2011-2930", "CVE-2011-2931", "CVE-2011-3186" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2011-09-21 05:47:11 +0200 (Wed, 21 Sep 2011)" );
	script_bugtraq_id( 49179 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "FreeBSD Ports: rubygem-rails" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following package is affected: rubygem-rails" );
	script_tag( name: "solution", value: "Update your system with the appropriate patches or
  software upgrades." );
	script_xref( name: "URL", value: "http://groups.google.com/group/rubyonrails-security/browse_thread/thread/6a1e473744bc389a" );
	script_xref( name: "URL", value: "http://groups.google.com/group/rubyonrails-security/browse_thread/thread/3420ac71aed312d6" );
	script_xref( name: "URL", value: "http://groups.google.com/group/rubyonrails-security/browse_thread/thread/6ffc93bde0298768" );
	script_xref( name: "URL", value: "http://groups.google.com/group/rubyonrails-security/browse_thread/thread/2b9130749b74ea12" );
	script_xref( name: "URL", value: "http://groups.google.com/group/rubyonrails-security/browse_thread/thread/56bffb5923ab1195" );
	script_xref( name: "URL", value: "http://www.vuxml.org/freebsd/be77eff6-ca91-11e0-aea3-00215c6a37bb.html" );
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
bver = portver( pkg: "rubygem-rails" );
if(!isnull( bver ) && revcomp( a: bver, b: "3.0.10" ) < 0){
	txt += "Package rubygem-rails version " + bver + " is installed which is known to be vulnerable.\n";
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

