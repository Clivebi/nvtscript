if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882260" );
	script_version( "$Revision: 14058 $" );
	script_cve_id( "CVE-2015-4473", "CVE-2015-4487", "CVE-2015-4488", "CVE-2015-4489", "CVE-2015-4491" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-08-28 05:05:22 +0200 (Fri, 28 Aug 2015)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "CentOS Update for thunderbird CESA-2015:1682 centos6" );
	script_tag( name: "summary", value: "Check the version of thunderbird" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Mozilla Thunderbird is a standalone mail and newsgroup client.

Several flaws were found in the processing of malformed web content. A web
page containing malicious content could cause Thunderbird to crash or,
potentially, execute arbitrary code with the privileges of the user running
Thunderbird. (CVE-2015-4473, CVE-2015-4491, CVE-2015-4487, CVE-2015-4488,
CVE-2015-4489)

Note: All of the above issues cannot be exploited by a specially crafted
HTML mail message because JavaScript is disabled by default for mail
messages. However, they could be exploited in other ways in Thunderbird
(for example, by viewing the full remote content of an RSS feed).

Red Hat would like to thank the Mozilla project for reporting these
issues. Upstream acknowledges Gary Kwong, Christian Holler, Byron Campen,
Gustavo Grieco, and Ronald Crane as the original reporters of these issues.

For technical details regarding these flaws, refer to the Mozilla security
advisories for Thunderbird 38.2. You can find a link to the Mozilla
advisories in the References section of this erratum.

All Thunderbird users should upgrade to this updated package, which
contains Thunderbird version 38.2, which corrects these issues.
After installing the update, Thunderbird must be restarted for the changes
to take effect." );
	script_tag( name: "affected", value: "thunderbird on CentOS 6" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_xref( name: "CESA", value: "2015:1682" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2015-August/021348.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS6" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "CentOS6"){
	if(( res = isrpmvuln( pkg: "thunderbird", rpm: "thunderbird~38.2.0~4.el6.centos", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

