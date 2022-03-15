if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71871" );
	script_cve_id( "CVE-2012-4377", "CVE-2012-4378", "CVE-2012-4379", "CVE-2012-4380", "CVE-2012-4381", "CVE-2012-4382" );
	script_version( "2021-08-27T12:28:31+0000" );
	script_tag( name: "last_modification", value: "2021-08-27 12:28:31 +0000 (Fri, 27 Aug 2021)" );
	script_tag( name: "creation_date", value: "2012-09-07 11:47:17 -0400 (Fri, 07 Sep 2012)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-02-12 18:48:00 +0000 (Wed, 12 Feb 2020)" );
	script_name( "FreeBSD Ports: mediawiki" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 E-Soft Inc." );
	script_family( "FreeBSD Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/freebsd", "ssh/login/freebsdrel" );
	script_tag( name: "insight", value: "The following package is affected: mediawiki" );
	script_tag( name: "solution", value: "Update your system with the appropriate patches or
  software upgrades." );
	script_xref( name: "URL", value: "https://bugzilla.wikimedia.org/show_bug.cgi?id=39700" );
	script_xref( name: "URL", value: "https://bugzilla.wikimedia.org/show_bug.cgi?id=37587" );
	script_xref( name: "URL", value: "https://bugzilla.wikimedia.org/show_bug.cgi?id=39180" );
	script_xref( name: "URL", value: "https://bugzilla.wikimedia.org/show_bug.cgi?id=39824" );
	script_xref( name: "URL", value: "https://bugzilla.wikimedia.org/show_bug.cgi?id=39184" );
	script_xref( name: "URL", value: "https://bugzilla.wikimedia.org/show_bug.cgi?id=39823" );
	script_xref( name: "URL", value: "http://www.vuxml.org/freebsd/7c0fecd6-f42f-11e1-b17b-000c2977ec30.html" );
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
bver = portver( pkg: "mediawiki" );
if(!isnull( bver ) && revcomp( a: bver, b: "1.19" ) >= 0 && revcomp( a: bver, b: "1.19.2" ) < 0){
	txt += "Package mediawiki version " + bver + " is installed which is known to be vulnerable.\\n";
	vuln = TRUE;
}
if(!isnull( bver ) && revcomp( a: bver, b: "1.18" ) >= 0 && revcomp( a: bver, b: "1.18.5" ) < 0){
	txt += "Package mediawiki version " + bver + " is installed which is known to be vulnerable.\\n";
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

