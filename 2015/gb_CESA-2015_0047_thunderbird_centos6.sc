if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882092" );
	script_version( "$Revision: 14058 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-01-23 12:56:25 +0100 (Fri, 23 Jan 2015)" );
	script_cve_id( "CVE-2014-8634", "CVE-2014-8638", "CVE-2014-8639" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "CentOS Update for thunderbird CESA-2015:0047 centos6" );
	script_tag( name: "summary", value: "Check the version of thunderbird" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Mozilla Thunderbird is a standalone mail and newsgroup client.

Two flaws were found in the processing of malformed web content. A web page
containing malicious content could cause Firefox to crash or, potentially,
execute arbitrary code with the privileges of the user running Firefox.
(CVE-2014-8634, CVE-2014-8639)

It was found that the Beacon interface implementation in Thunderbird did
not follow the Cross-Origin Resource Sharing (CORS) specification. A web
page containing malicious content could allow a remote attacker to conduct
a Cross-Site Request Forgery (XSRF) attack. (CVE-2014-8638)

Note: All of the above issues cannot be exploited by a specially crafted
HTML mail message as JavaScript is disabled by default for mail messages.
They could be exploited another way in Thunderbird, for example, when
viewing the full remote content of an RSS feed.

Red Hat would like to thank the Mozilla project for reporting these issues.
Upstream acknowledges Christian Holler, Patrick McManus, Muneaki Nishimura,
and Xiaofeng Zheng as the original reporters of these issues.

For technical details regarding these flaws, refer to the Mozilla security
advisories for Thunderbird 31.4.0. You can find a link to the Mozilla
advisories in the References section of this erratum.

All Thunderbird users should upgrade to this updated package, which
contains Thunderbird version 31.4.0, which corrects these issues.
After installing the update, Thunderbird must be restarted for the changes
to take effect." );
	script_tag( name: "affected", value: "thunderbird on CentOS 6" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_xref( name: "CESA", value: "2015:0047" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2015-January/020872.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
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
	if(( res = isrpmvuln( pkg: "thunderbird", rpm: "thunderbird~31.4.0~1.el6.centos", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

