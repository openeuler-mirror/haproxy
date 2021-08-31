%define haproxy_user      haproxy
%define haproxy_group     haproxy

%global _hardened_build   1

Name:             haproxy
Version:          2.2.16
Release:          1
Summary:          The Reliable, High Performance TCP/HTTP Load Balancer

License:          GPLv2+
URL:              http://www.haproxy.org/
Source0:          http://www.haproxy.org/download/2.2/src/%{name}-%{version}.tar.gz
Source1:          %{name}.service
Source2:          %{name}.cfg
Source3:          %{name}.logrotate
Source4:          %{name}.sysconfig

BuildRequires:    gcc lua-devel pcre-devel zlib-devel openssl-devel systemd-devel systemd-units libatomic
Requires(pre):    shadow-utils
Requires(post):   systemd
Requires(preun):  systemd
Requires(postun): systemd

%package_help
%description
HAProxy is a free, very fast and reliable solution offering high availability, load balancing,
and proxying for TCP and HTTP-based applications. It is particularly suited for very high traffic
web sites and powers quite a number of the world's most visited ones. 

%prep
%autosetup -n %{name}-%{version} -p1

%build
use_regparm_opt=
%ifarch %ix86 x86_64
use_regparm_opt="USE_REGPARM=1"
%endif

%make_build CPU="generic" TARGET="linux-glibc" USE_OPENSSL=1 USE_PCRE=1 USE_ZLIB=1 \
    USE_LUA=1 USE_CRYPT_H=1 USE_SYSTEMD=1 USE_LINUX_TPROXY=1 USE_GETADDRINFO=1 ${use_regparm_opt} \
    ADDINC="%{optflags}" ADDLIB="%{__global_ldflags}"

pushd contrib/halog
%make_build ${halog} OPTIMIZE="%{optflags} %{build_ldflags}"
popd

pushd contrib/iprange
%make_build iprange OPTIMIZE="%{optflags} %{build_ldflags}"
popd

%install
install -d %{buildroot}%{_sbindir}
install haproxy  %{buildroot}%{_sbindir}
install -d %{buildroot}%{_mandir}/man1
install -m 644 doc/haproxy.1 %{buildroot}%{_mandir}/man1

pushd %{buildroot}
install -p -D -m 0644 %{SOURCE1} .%{_unitdir}/%{name}.service
install -p -D -m 0644 %{SOURCE2} .%{_sysconfdir}/haproxy/%{name}.cfg
install -p -D -m 0644 %{SOURCE3} .%{_sysconfdir}/logrotate.d/%{name}
install -p -D -m 0644 %{SOURCE4} .%{_sysconfdir}/sysconfig/%{name}
install -d -m 0755 .%{_bindir}
install -d -m 0755 .%{_localstatedir}/lib/haproxy
install -d -m 0755 .%{_datadir}/haproxy
popd

install -p -m 0755 ./contrib/halog/halog %{buildroot}%{_bindir}/halog
install -p -m 0755 ./contrib/iprange/iprange %{buildroot}%{_bindir}/iprange
install -p -m 0644 ./examples/errorfiles/* %{buildroot}%{_datadir}/haproxy

for httpfile in $(find ./examples/errorfiles/ -type f) 
do
    install -p -m 0644 $httpfile %{buildroot}%{_datadir}/haproxy
done

%{__rm} -rf ./examples/errorfiles/
find ./examples/* -type f ! -name "*.cfg" -exec %{__rm} -f "{}" \;

textfiles=$(find ./ -type f -name '*.txt')
for textfile in ${textfiles}
do
    %{__mv} ${textfile} ${textfile}.old
    iconv --from-code ISO8859-1 --to-code UTF-8 --output ${textfile} ${textfile}.old
    %{__rm} -f ${textfile}.old
done

%pre
getent group %{haproxy_group} >/dev/null || groupadd -r %{haproxy_group}
getent passwd %{haproxy_user} >/dev/null || useradd -r -g %{haproxy_user} -d \
    %{_localstatedir}/lib/haproxy -s /sbin/nologin -c "haproxy" %{haproxy_user}
exit 0

%post
%systemd_post %{name}.service

%preun
%systemd_preun %{name}.service

%postun
%systemd_postun_with_restart %{name}.service

%files
%defattr(-,root,root)
%license LICENSE
%dir %{_sysconfdir}/haproxy
%config(noreplace) %{_sysconfdir}/haproxy/%{name}.cfg
%config(noreplace) %{_sysconfdir}/logrotate.d/%{name}
%config(noreplace) %{_sysconfdir}/sysconfig/%{name}
%{_bindir}/halog
%{_bindir}/iprange
%{_sbindir}/%{name}
%{_unitdir}/%{name}.service
%dir %{_localstatedir}/lib/haproxy
%dir %{_datadir}/haproxy
%{_datadir}/haproxy/*

%files help
%defattr(-,root,root)
%doc doc/* examples/* CHANGELOG README ROADMAP VERSION
%{_mandir}/man1/*

%changelog
* Wed Aug 31 2021 yaoxin <yaoxin30@huawei.com> - 2.2.16-1
- Upgrade 2.2.16 to fix CVE-2021-39240-to-CVE-2021-39242

* Wed Aug 12 2020 gaihuiying <gaihuiying1@huawei.com> - 2.0.14-1
- Type:requirement
- ID:NA
- SUG:NA
- DESC:update sendmail to 2.0.14

* Thu May 7 2020 cuibaobao <cuibaobao1@huawei.com> - 1.8.14-5
- Type:cves
- ID: CVE-2020-11100
- SUG:restart
- DESC: fix CVE-2020-11100

* Wed Dec 4 2019 openEuler Buildteam <buildteam@openeuler.org> - 1.8.14-4
- Package init 
