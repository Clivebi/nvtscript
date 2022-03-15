if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844991" );
	script_version( "2021-08-19T14:00:55+0000" );
	script_cve_id( "CVE-2021-23961", "CVE-2021-23981", "CVE-2021-23982", "CVE-2021-23987", "CVE-2021-23994", "CVE-2021-23998", "CVE-2021-23999", "CVE-2021-29945", "CVE-2021-29946", "CVE-2021-29967", "CVE-2021-23984", "CVE-2021-23991", "CVE-2021-23992", "CVE-2021-23993", "CVE-2021-23995", "CVE-2021-24002", "CVE-2021-29948", "CVE-2021-29949", "CVE-2021-29956", "CVE-2021-29957" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-19 14:00:55 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-24 14:15:00 +0000 (Thu, 24 Jun 2021)" );
	script_tag( name: "creation_date", value: "2021-06-26 03:00:22 +0000 (Sat, 26 Jun 2021)" );
	script_name( "Ubuntu: Security Advisory for thunderbird (USN-4995-2)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU18\\.04 LTS" );
	script_xref( name: "Advisory-ID", value: "USN-4995-2" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2021-June/006092.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'thunderbird'
  package(s) announced via the USN-4995-2 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "USN-4995-1 fixed vulnerabilities in Thunderbird. This update provides
the corresponding updates for Ubuntu 18.04 LTS.

Original advisory details:

Multiple security issues were discovered in Thunderbird. If a user were
tricked into opening a specially crafted website in a browsing context, an
attacker could potentially exploit these to cause a denial of service,
obtain sensitive information, spoof the UI, bypass security restrictions,
or execute arbitrary code. (CVE-2021-23961, CVE-2021-23981,
CVE-2021-23982, CVE-2021-23987, CVE-2021-23994, CVE-2021-23998,
CVE-2021-23999, CVE-2021-29945, CVE-2021-29946, CVE-2021-29967)
It was discovered that extensions could open popup windows with control
of the window title in some circumstances. If a user were tricked into
installing a specially crafted extension, an attacker could potentially
exploit this to spoof a website and trick the user into providing
credentials. (CVE-2021-23984)
Multiple security issues were discovered in Thunderbird's OpenPGP
integration. If a user were tricked into importing a specially crafted
key in some circumstances, an attacker could potentially exploit this
to cause a denial of service (inability to send encrypted email) or
confuse the user. (CVE-2021-23991, CVE-2021-23992, CVE-2021-23993)
A use-after-free was discovered when Responsive Design Mode was
enabled. If a user were tricked into opening a specially crafted
website with Responsive Design Mode enabled, an attacker could
potentially exploit this to cause a denial of service, or execute
arbitrary code. (CVE-2021-23995)
It was discovered that Thunderbird mishandled ftp URLs with encoded
newline characters. If a user were tricked into clicking on a specially
crafted link, an attacker could potentially exploit this to send arbitrary
FTP commands. (CVE-2021-24002)
It was discovered that Thunderbird wrote signatures to disk and read them
back during verification. A local attacker could potentially exploit this
to replace the data with another signature file. (CVE-2021-29948)
It was discovered that Thunderbird might load an alternative OTR
library. If a user were tricked into copying a specially crafted
library to one of Thunderbird's search paths, an attacker could
potentially exploit this to execute arbitrary code. (CVE-2021-29949)
It was discovered that secret keys imported into Thunderbird were
stored unencrypted. A local attacker could potentially exploit this to
obtain private keys. (CVE-2021-29956)
It was discovered that Thunderbird did not indicate when an inline signed
or encrypted message contained additional unprotected parts.
(CVE-2021-29957)" );
	script_tag( name: "affected", value: "'thunderbird' package(s) on Ubuntu 18.04 LTS." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
report = "";
if(release == "UBUNTU18.04 LTS"){
	if(!isnull( res = isdpkgvuln( pkg: "thunderbird", ver: "1:78.11.0+build1-0ubuntu0.18.04.2", rls: "UBUNTU18.04 LTS" ) )){
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
	exit( 0 );
}
exit( 0 );

