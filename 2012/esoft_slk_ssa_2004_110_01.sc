if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.53939" );
	script_tag( name: "creation_date", value: "2012-09-11 01:34:21 +0200 (Tue, 11 Sep 2012)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 10:16:15 +0100 (Fri, 15 Mar 2019) $" );
	script_bugtraq_id( 10178 );
	script_cve_id( "CVE-2004-0233" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:P/A:N" );
	script_version( "$Revision: 14202 $" );
	script_name( "Slackware Advisory SSA:2004-110-01 utempter security update" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Slackware Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/slackware_linux", "ssh/login/slackpack",  "ssh/login/release=SLK9\\.1" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=SSA:2004-110-01" );
	script_tag( name: "insight", value: "New utempter packages are available for Slackware 9.1 and -current to
fix a security issue.  (Slackware 9.1 was the first version of Slackware
to use the libutempter library, and earlier versions of Slackware are
not affected by this issue)

The utempter package provides a utility and shared library that
allows terminal applications such as xterm and screen to update
/var/run/utmp and /var/log/wtmp without requiring root privileges.
Steve Grubb has identified an issue with utempter-0.5.2 where
under certain circumstances an attacker could cause it to
overwrite files through a symlink.  This has been addressed by
upgrading the utempter package to use Dmitry V. Levin's new
implementation of libutempter that does not have this bug." );
	script_tag( name: "solution", value: "Upgrade to the new package(s)." );
	script_tag( name: "summary", value: "The remote host is missing an update as announced
via advisory SSA:2004-110-01." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-slack.inc.sc");
report = "";
res = "";
if(( res = isslkpkgvuln( pkg: "utempter", ver: "1.1.1-i486-1", rls: "SLK9.1" ) ) != NULL){
	report += res;
}
if( report != "" ){
	security_message( data: report );
}
else {
	if(__pkg_match){
		exit( 99 );
	}
}

