if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.69992" );
	script_version( "$Revision: 11762 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-05 12:54:12 +0200 (Fri, 05 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2011-08-03 04:36:20 +0200 (Wed, 03 Aug 2011)" );
	script_tag( name: "cvss_base", value: "5.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2011-1097" );
	script_name( "FreeBSD Ports: rsync" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following package is affected: rsync

CVE-2011-1097
rsync 3.x before 3.0.8, when certain recursion, deletion, and
ownership options are used, allows remote rsync servers to cause a
denial of service (heap memory corruption and application crash) or
possibly execute arbitrary code via malformed data." );
	script_tag( name: "solution", value: "Update your system with the appropriate patches or
  software upgrades." );
	script_xref( name: "URL", value: "https://bugzilla.samba.org/show_bug.cgi?id=7936" );
	script_xref( name: "URL", value: "http://www.vuxml.org/freebsd/9a777c23-b310-11e0-832d-00215c6a37bb.html" );
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
bver = portver( pkg: "rsync" );
if(!isnull( bver ) && revcomp( a: bver, b: "3.0" ) > 0 && revcomp( a: bver, b: "3.0.8" ) < 0){
	txt += "Package rsync version " + bver + " is installed which is known to be vulnerable.\n";
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

