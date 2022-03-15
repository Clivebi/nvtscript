if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.53887" );
	script_tag( name: "creation_date", value: "2012-09-11 01:34:21 +0200 (Tue, 11 Sep 2012)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 10:16:15 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_version( "$Revision: 14202 $" );
	script_name( "Slackware Advisory SSA:2003-251-01 inetd DoS patched" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Slackware Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/slackware_linux", "ssh/login/slackpack",  "ssh/login/release=SLK(8\\.1|9\\.0)" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=SSA:2003-251-01" );
	script_tag( name: "insight", value: "Upgraded inetd packages are available for Slackware 8.1, 9.0 and -current.

  These fix a previously hard-coded limit of 256
connections-per-minute, after which the given service is disabled
for ten minutes.  An attacker could use a quick burst of
connections every ten minutes to effectively disable a service.

Once upon a time, this was an intentional feature of inetd, but in
today's world it has become a bug.  Even having inetd look at the
source IP and try to limit only the source of the attack would be
problematic since TCP source addresses are so easily faked.  So,
the approach we have taken (borrowed from FreeBSD) is to disable
this rate limiting 'feature' by default.  It can be re-enabled by
providing a -R <rate> option on the command-line if desired, but
for obvious reasons we do not recommend this.

Any site running services through inetd that they would like
protected from this simple DoS attack should upgrade to the new
inetd package immediately." );
	script_tag( name: "solution", value: "Upgrade to the new package(s)." );
	script_tag( name: "summary", value: "The remote host is missing an update as announced
via advisory SSA:2003-251-01." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-slack.inc.sc");
report = "";
res = "";
if(( res = isslkpkgvuln( pkg: "inetd", ver: "1.79s-i386-2", rls: "SLK8.1" ) ) != NULL){
	report += res;
}
if(( res = isslkpkgvuln( pkg: "inetd", ver: "1.79s-i386-2", rls: "SLK9.0" ) ) != NULL){
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

