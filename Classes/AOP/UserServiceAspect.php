<?php
declare(strict_types=1);

namespace PunktDe\FrontendUserPatch\AOP;

/*
 *  (c) 2021 punkt.de GmbH - Karlsruhe, Germany - https://punkt.de
 *  All rights reserved.
 */

use Neos\Flow\Annotations as Flow;
use Neos\Flow\Aop\JoinPointInterface;
use Neos\Flow\Security\Account;
use Neos\Neos\Domain\Model\User;
use Neos\Flow\Security\Authentication\TokenInterface;
use Neos\Flow\Security\Context;
use Neos\Party\Domain\Service\PartyService;

/**
 * @Flow\Aspect
 */
class UserServiceAspect
{

    /**
     * @Flow\Inject
     * @var Context
     */
    protected $securityContext;

    /**
     * @Flow\Inject
     * @var PartyService
     */
    protected $partyService;

    /**
     * @var array
     */
    protected $runtimeUserCache = [];


    /**
     * @Flow\Around("method(Neos\Neos\Domain\Service\UserService->getCurrentUser())")
     *
     * @param JoinPointInterface $joinPoint The current joinPoint
     */
    public function getCurrentUser(JoinPointInterface $joinPoint)
    {
        if ($this->securityContext->canBeInitialized() === false) {
            return null;
        }

        $runtimeCacheIdentifier = 'sec-context-' . $this->securityContext->getContextHash();
        if (array_key_exists($runtimeCacheIdentifier, $this->runtimeUserCache)) {
            return $this->runtimeUserCache[$runtimeCacheIdentifier];
        }

        $tokens = $this->securityContext->getAuthenticationTokens();
        $user = array_reduce($tokens, function ($foundUser, TokenInterface $token) {
            if ($foundUser !== null) {
                return $foundUser;
            }

            $account = $token->getAccount();
            if ($account === null) {
                return $foundUser;
            }

            $user = $this->getNeosUserForAccount($account);
            if ($user === null) {
                return $foundUser;
            }

            return $user;
        }, null);

        $this->runtimeUserCache[$runtimeCacheIdentifier] = $user;
        return $user;
    }


    /**
     * @param Account $account
     * @return User|null
     */
    private function getNeosUserForAccount(Account $account):? User
    {
        $user = $this->partyService->getAssignedPartyOfAccount($account);
        return ($user instanceof User) ? $user : null;
    }
}
