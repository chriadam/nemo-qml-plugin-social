/*
 * Copyright (C) 2013 Jolla Ltd. <chris.adams@jollamobile.com>
 *
 * You may use this file under the terms of the BSD license as follows:
 *
 * "Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Nemo Mobile nor the names of its contributors
 *     may be used to endorse or promote products derived from this
 *     software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE."
 */

#ifndef TWITTERINTERFACE_P_H
#define TWITTERINTERFACE_P_H

#include "socialnetworkinterface.h"
#include "socialnetworkinterface_p.h"
#include "twitterinterface.h"

#include <QtCore/QObject>
#include <QtCore/QVariantMap>
#include <QtCore/QStringList>
#include <QtCore/QString>
#include <QtCore/QUrl>
#include <QtNetwork/QNetworkReply>
#include <QtNetwork/QSslError>

class ContentItemInterface;

class TwitterInterfacePrivate : public SocialNetworkInterfacePrivate
{
public:
    explicit TwitterInterfacePrivate(TwitterInterface *q);

    QString oauthToken;
    QString oauthTokenSecret;
    QString consumerKey;
    QString consumerSecret;
    QString currentUserIdentifier;

    bool populatePending;
    bool populateDataForUnseenPending;
    bool continuationRequestActive;

    int outOfBandConnectionsLimit;

    enum InternalStatus {
        Idle = 0,
        PopulatingSeenNode,
        PopulatingUnseenNode,
        Other
    };
    InternalStatus internalStatus; // used for state machine in reply finished.

    void setCurrentReply(QNetworkReply *newCurrentReply, const QString &whichNodeIdentifier);
    QNetworkReply *currentReply; // this should never be set directly, always use the above mutator.

    QUrl requestUrl(const QString &objectId, const QString &extraPath, const QStringList &whichFields, const QVariantMap &extraData);

    int detectTypeFromData(const QVariantMap &data) const;

    void connectFinishedAndErrors();

    // Slots
    void finishedHandler();
    void errorHandler(QNetworkReply::NetworkError err);
    void sslErrorsHandler(const QList<QSslError> &errs);
    void deleteReply();

public:
    // the following is for identifiable content item "actions"
    enum TwitterAction {
        NoAction = 0,
        RemoveAction,
        ReloadAction,
        FollowAction,
        UnfollowAction,
        TweetAction,
        RetweetAction
    };
private:
    Q_DECLARE_PUBLIC(TwitterInterface)
};

#endif // TWITTERINTERFACE_P_H